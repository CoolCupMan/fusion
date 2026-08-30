package com.fusion.firewall.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.ServiceCompat
import com.fusion.firewall.FusionApp
import com.fusion.firewall.R
import com.fusion.firewall.data.ConnectionLog
import com.fusion.firewall.data.FusionSettings
import com.fusion.firewall.data.model.ConnectionEvent
import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.data.model.Transport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * The heart of Fusion. A [VpnService] built as a reliable blocking firewall +
 * blocked-traffic monitor (no userspace TCP/IP stack required):
 *
 *  - BLOCK   -> app is routed into the tunnel; each connection attempt is read
 *              for the live view + AI classification, then dropped (no network).
 *  - ALLOW / PENDING -> app is added as a disallowed application, so it bypasses
 *              the tunnel and keeps normal connectivity. (PENDING is captured
 *              instead only when "block pending" is enabled.)
 *
 * Because only blocked apps are routed, enabling Fusion never takes the phone
 * offline, and the live monitor shows exactly the traffic you chose to inspect.
 */
class FusionVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var app: FusionApp

    @Volatile private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var packetThread: Thread? = null
    @Volatile private var reestablishJob: kotlinx.coroutines.Job? = null

    @Volatile private var settings: FusionSettings = FusionSettings()
    @Volatile private var rules: Map<String, Policy> = emptyMap()

    // uid -> effective policy, rebuilt on each establish for the packet loop.
    private val effectivePolicy = ConcurrentHashMap<Int, Policy>()
    private val seenFlows = ConcurrentHashMap.newKeySet<String>()
    private val promptedUids = ConcurrentHashMap.newKeySet<Int>()

    override fun onCreate() {
        super.onCreate()
        app = application as FusionApp
        // Track config changes and re-establish the tunnel while running.
        combine(app.container.repository.rules, app.container.repository.settings) { r, s -> r to s }
            .onEach { (r, s) ->
                rules = r
                settings = s
                // Debounce: rebuild the tunnel shortly after rules/settings settle
                // (e.g. blocking several apps quickly) instead of on every keystroke.
                if (isRunning.value) {
                    reestablishJob?.cancel()
                    reestablishJob = scope.launch {
                        kotlinx.coroutines.delay(350)
                        establish()
                    }
                }
            }
            .launchIn(scope)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopForegroundCompat()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForegroundNotification()
                scope.launch {
                    rules = app.container.repository.rules.first()
                    settings = app.container.repository.settings.first()
                    app.container.repository.setFirewallEnabled(true)
                    establish()
                }
            }
        }
        return START_STICKY
    }

    @Synchronized
    private fun establish() {
        val installed = app.container.appInfo.loadAll()
        effectivePolicy.clear()
        seenFlows.clear()
        promptedUids.clear()

        val builder = Builder()
            .setSession(getString(R.string.vpn_session))
            .setMtu(1500)
            .addAddress("10.99.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDisallowedApplication(packageName) // never capture ourselves

        // IPv6 sink so v6-capable apps are governed too (ULA address).
        runCatching {
            builder.addAddress("fd00:2025:c0de::1", 64).addRoute("::", 0)
        }

        // Capture (route + monitor) any app whose effective policy is not ALLOW:
        //  - BLOCK   -> dropped (no connectivity).
        //  - PENDING -> unconfirmed: monitored in realtime and personally prompted
        //               (this only happens when the default policy is "Ask", so
        //               with the default "Allow" the phone is never taken offline).
        // Everything else bypasses the tunnel and keeps normal connectivity.
        for (info in installed) {
            if (info.packageName == packageName) continue
            val effective = effectiveFor(info.packageName)
            effectivePolicy[info.uid] = effective
            if (effective == Policy.ALLOW) {
                runCatching { builder.addDisallowedApplication(info.packageName) }
            }
        }

        val newTunnel = runCatching { builder.establish() }.getOrNull()
        if (newTunnel == null) {
            stopTunnel(); stopSelf(); return
        }

        // Swap the descriptor; the old read loop unblocks and exits.
        val old = tunnel
        tunnel = newTunnel
        old?.let { runCatching { it.close() } }
        isRunning.value = true

        startPacketLoop(newTunnel)
    }

    private fun effectiveFor(pkg: String): Policy =
        rules[pkg] ?: settings.defaultPolicy

    private fun startPacketLoop(fd: ParcelFileDescriptor) {
        packetThread?.interrupt()
        val thread = Thread({ readLoop(fd) }, "fusion-packets")
        thread.isDaemon = true
        packetThread = thread
        thread.start()
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (!Thread.currentThread().isInterrupted && tunnel === fd) {
                val n = input.read(buffer)
                if (n <= 0) {
                    if (n < 0) break else continue
                }
                val packet = PacketParser.parse(buffer, n) ?: continue
                handlePacket(buffer, packet)
                // No write-back: captured packets are dropped (blocked).
            }
        } catch (_: Exception) {
            // fd closed on re-establish/stop — normal.
        } finally {
            runCatching { input.close() }
        }
    }

    private fun handlePacket(buffer: ByteArray, packet: ParsedPacket) {
        if (packet.transport == Transport.ICMP || packet.transport == Transport.OTHER) return
        if (packet.destPort == 0) return

        val uid = resolveUid(packet)
        val flowId = "$uid|${packet.destIp}|${packet.destPort}|${packet.transport}"
        if (!seenFlows.add(flowId)) return // already surfaced this flow
        if (seenFlows.size > 4000) seenFlows.clear()

        val info = if (uid > 0) app.container.appInfo.appForUid(uid) else null
        val hostname = if (packet.transport == Transport.UDP && packet.destPort == 53) {
            PacketParser.dnsQueryName(buffer, packet.payloadOffset, packet.length)
        } else {
            app.container.hosts.cached(packet.destIp)
        }

        val flagged = app.container.hosts.isKnownTracker(hostname)
        val event = ConnectionEvent(
            timestamp = System.currentTimeMillis(),
            uid = uid,
            packageName = info?.packageName,
            appLabel = info?.label ?: labelForUid(uid),
            transport = packet.transport,
            direction = packet.direction,
            remoteIp = packet.destIp,
            remotePort = packet.destPort,
            localPort = packet.sourcePort,
            hostname = hostname,
            bytes = packet.length,
            allowed = false,
            flagged = flagged,
            flagReason = if (flagged) "known tracker/telemetry" else null,
        )
        ConnectionLog.record(event)

        maybePrompt(uid, info?.label, info?.packageName)
        assessAsync(event, info?.system == true)
    }

    private fun resolveUid(packet: ParsedPacket): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        val cm = getSystemService(ConnectivityManager::class.java) ?: return -1
        val proto = if (packet.transport == Transport.TCP) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP
        return runCatching {
            val local = InetSocketAddress(InetAddress.getByName(packet.sourceIp), packet.sourcePort)
            val remote = InetSocketAddress(InetAddress.getByName(packet.destIp), packet.destPort)
            cm.getConnectionOwnerUid(proto, local, remote)
        }.getOrDefault(-1)
    }

    private fun labelForUid(uid: Int): String = when {
        uid <= 0 -> "Unresolved"
        else -> "uid $uid"
    }

    private fun maybePrompt(uid: Int, label: String?, pkg: String?) {
        if (!settings.promptOnNewApps || pkg == null) return
        if (effectiveFor(pkg) != Policy.PENDING) return
        if (!promptedUids.add(uid)) return
        NotificationHelper.promptForApp(this, uid, label ?: pkg, pkg)
    }

    private fun assessAsync(event: ConnectionEvent, isSystem: Boolean) {
        val pkg = event.packageName ?: return
        scope.launch {
            val ctx = com.fusion.firewall.ai.ConnectionContext(
                appLabel = event.appLabel ?: pkg,
                packageName = pkg,
                isSystemApp = isSystem,
                host = event.hostname,
                ip = event.remoteIp,
                port = event.remotePort,
                transport = event.transport,
            )
            val assessment = app.container.binaryCore.assess(ctx, settings)
            // Publish the verdict so the recommendation lists can categorize this
            // connection as safe / suspicious / malicious without a manual tap.
            ConnectionLog.recordAssessment(event.id, assessment)
            if (settings.aiAutoApply &&
                assessment.recommendedPolicy != Policy.PENDING &&
                effectiveFor(pkg) == Policy.PENDING
            ) {
                app.container.repository.setPolicy(pkg, assessment.recommendedPolicy)
            }
        }
    }

    private fun startForegroundNotification() {
        NotificationHelper.ensureChannels(this)
        startForegroundCompat(NotificationHelper.serviceNotification(this))
    }

    private fun startForegroundCompat(notification: android.app.Notification) {
        // No foreground-service type: keeps the package parseable on Android 13
        // and below while still running fine on Android 14 (targetSdk 33).
        ServiceCompat.startForeground(this, NOTIF_ID, notification, 0)
    }

    private fun stopForegroundCompat() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    private fun stopTunnel() {
        isRunning.value = false
        packetThread?.interrupt()
        packetThread = null
        tunnel?.let { runCatching { it.close() } }
        tunnel = null
        scope.launch { app.container.repository.setFirewallEnabled(false) }
    }

    override fun onDestroy() {
        stopTunnel()
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        stopForegroundCompat()
        stopSelf()
        super.onRevoke()
    }

    companion object {
        const val ACTION_START = "com.fusion.firewall.START"
        const val ACTION_STOP = "com.fusion.firewall.STOP"
        private const val NOTIF_ID = 1001

        /** Realtime running state observable by the UI. */
        val isRunning: MutableStateFlow<Boolean> = MutableStateFlow(false)
        val running: StateFlow<Boolean> = isRunning.asStateFlow()

        fun start(context: Context) {
            val intent = Intent(context, FusionVpnService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, FusionVpnService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }
    }
}
