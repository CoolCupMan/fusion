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
import com.fusion.firewall.data.model.Direction
import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.data.model.Transport
import com.fusion.firewall.dns.DnsFilter
import com.fusion.firewall.dns.Ipv4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Fusion's realtime engine, implemented as an on-device **DNS filter** (like
 * Pi-hole): the VPN intercepts DNS only, so every app stays online, and each
 * lookup is checked against the active block lists + whitelist. Blocked names are
 * sinkholed (NXDOMAIN) instantly; everything else is forwarded to the real
 * resolver. Per-app blocks sinkhole every lookup from that app.
 *
 * Only DNS is routed into the tunnel (the fake resolver 10.0.0.1), so no
 * userspace TCP/IP stack is needed and normal traffic is untouched.
 */
class FusionVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var app: FusionApp

    @Volatile private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var packetThread: Thread? = null
    @Volatile private var refreshJob: Job? = null
    @Volatile private var upstreams: List<InetAddress> = defaultUpstreams()
    @Volatile private var settings: FusionSettings = FusionSettings()
    @Volatile private var rules: Map<String, Policy> = emptyMap()

    private val seenAllowed = ConcurrentHashMap.newKeySet<String>()

    // Realtime heuristic: distinct tracker domains seen per app uid, and uids
    // we have already auto-blocked this session.
    private val uidTrackers = ConcurrentHashMap<Int, MutableSet<String>>()
    private val autoBlockedUids = ConcurrentHashMap.newKeySet<Int>()
    private val dangerTrackerThreshold = 6

    override fun onCreate() {
        super.onCreate()
        app = application as FusionApp
        app.container.repository.settings.onEach { settings = it }.launchIn(scope)
        app.container.repository.rules.onEach { rules = it }.launchIn(scope)
        // Rebuild the blocker whenever rules or any block list change (no tunnel
        // rebuild needed — the filter reads the blocker live).
        combine(
            app.container.repository.rules,
            app.container.blockLists.lists,
            app.container.blockLists.custom,
            app.container.blockLists.whitelist,
        ) { _, _, _, _ -> Unit }
            .onEach {
                if (isRunning.value) {
                    refreshJob?.cancel()
                    refreshJob = scope.launch { delay(250); refreshBlocker() }
                }
            }
            .launchIn(scope)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel(); stopForegroundCompat(); stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForegroundNotification()
                scope.launch {
                    app.container.repository.setFirewallEnabled(true)
                    refreshUpstreams()
                    refreshBlocker()
                    establish()
                }
            }
        }
        return START_STICKY
    }

    private suspend fun refreshBlocker() {
        val domains = app.container.blockLists.activeDomains()
        val white = app.container.blockLists.whitelist.first()
        val rules = app.container.repository.rules.first()
        val installed = app.container.appInfo.loadAll()
        val blockedUids = installed.filter { rules[it.packageName] == Policy.BLOCK }.map { it.uid }.toSet()
        app.container.domainBlocker.update(domains, white, blockedUids)
    }

    private fun refreshUpstreams() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val servers = runCatching {
            val net = cm.activeNetwork ?: return@runCatching emptyList<InetAddress>()
            cm.getLinkProperties(net)?.dnsServers?.filterIsInstance<Inet4Address>() ?: emptyList()
        }.getOrDefault(emptyList())
        upstreams = (servers + defaultUpstreams()).distinct().ifEmpty { defaultUpstreams() }
    }

    private fun establish() {
        val builder = Builder()
            .setSession(getString(R.string.vpn_session))
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("10.0.0.1", 32)
        runCatching { builder.addDisallowedApplication(packageName) }

        val newTunnel = runCatching { builder.establish() }.getOrNull()
        if (newTunnel == null) { stopTunnel(); stopSelf(); return }

        val old = tunnel
        tunnel = newTunnel
        old?.let { runCatching { it.close() } }
        isRunning.value = true
        seenAllowed.clear()
        startPacketLoop(newTunnel)
    }

    private fun startPacketLoop(fd: ParcelFileDescriptor) {
        packetThread?.interrupt()
        val thread = Thread({ readLoop(fd) }, "fusion-dns")
        thread.isDaemon = true
        packetThread = thread
        thread.start()
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (!Thread.currentThread().isInterrupted && tunnel === fd) {
                val n = input.read(buffer)
                if (n <= 0) { if (n < 0) break else continue }
                runCatching { handleDns(buffer, n, output) }
            }
        } catch (_: Exception) {
            // fd closed on stop — normal.
        } finally {
            runCatching { input.close() }
            runCatching { output.close() }
        }
    }

    private fun handleDns(buffer: ByteArray, n: Int, output: FileOutputStream) {
        if (n < 28) return
        if ((buffer[0].toInt() ushr 4) and 0xF != 4) return       // IPv4 only
        if ((buffer[9].toInt() and 0xFF) != 17) return             // UDP
        val ihl = (buffer[0].toInt() and 0x0F) * 4
        if (n < ihl + 8) return
        val dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
        if (dstPort != 53) return
        val srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)

        val payloadOff = ihl + 8
        val payload = buffer.copyOfRange(payloadOff, n)
        val query = DnsFilter.parseQuery(payload, payload.size) ?: return

        val srcIp = buffer.copyOfRange(12, 16)   // app (tun) address
        val dnsIp = buffer.copyOfRange(16, 20)   // 10.0.0.1
        val uid = resolveUid(srcIp, srcPort, dnsIp)

        val blocked = app.container.domainBlocker.isBlocked(query.name, uid)
        if (blocked) {
            val resp = DnsFilter.buildNxdomain(payload, query.questionEnd)
            runCatching { output.write(Ipv4.buildUdp(dnsIp, srcIp, 53, srcPort, resp)) }
            record(uid, query.name, blocked = true)
        } else {
            val resp = forward(payload)
            if (resp != null) {
                runCatching { output.write(Ipv4.buildUdp(dnsIp, srcIp, 53, srcPort, resp)) }
            }
            if (seenAllowed.add("$uid|${query.name}")) {
                if (seenAllowed.size > 3000) seenAllowed.clear()
                record(uid, query.name, blocked = false)
            }
        }
    }

    private fun forward(payload: ByteArray): ByteArray? {
        for (server in upstreams) {
            val sock = runCatching { DatagramSocket() }.getOrNull() ?: continue
            try {
                protect(sock)
                sock.soTimeout = 3000
                sock.send(DatagramPacket(payload, payload.size, server, 53))
                val buf = ByteArray(4096)
                val dp = DatagramPacket(buf, buf.size)
                sock.receive(dp)
                return buf.copyOf(dp.length)
            } catch (_: Exception) {
                // try next upstream
            } finally {
                runCatching { sock.close() }
            }
        }
        return null
    }

    private fun resolveUid(srcIp: ByteArray, srcPort: Int, dnsIp: ByteArray): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        val cm = getSystemService(ConnectivityManager::class.java) ?: return -1
        return runCatching {
            val local = InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort)
            val remote = InetSocketAddress(InetAddress.getByAddress(dnsIp), 53)
            cm.getConnectionOwnerUid(OsConstants.IPPROTO_UDP, local, remote)
        }.getOrDefault(-1)
    }

    private fun record(uid: Int, domain: String, blocked: Boolean) {
        val info = if (uid > 0) app.container.appInfo.appForUid(uid) else null
        maybeAutoBlockDangerous(uid, domain, info?.packageName)
        val byApp = blocked && app.container.domainBlocker.isBlockedUid(uid)
        val event = ConnectionEvent(
            timestamp = System.currentTimeMillis(),
            uid = uid,
            packageName = info?.packageName,
            appLabel = info?.label ?: if (uid <= 0) "Unresolved" else "uid $uid",
            transport = Transport.UDP,
            direction = Direction.OUTBOUND,
            remoteIp = "",
            remotePort = 53,
            localPort = 0,
            hostname = domain,
            bytes = domain.length,
            allowed = !blocked,
            flagged = blocked,
            flagReason = if (byApp) "blocked app" else if (blocked) "block list" else null,
        )
        ConnectionLog.record(event)
    }

    /**
     * Realtime heuristic auto-block: if an app contacts several distinct known
     * tracker/telemetry domains and the user enabled auto-block, permanently
     * block that app (sinkhole all its lookups). Manual ALLOW always wins, and
     * each app is auto-blocked at most once per session.
     */
    private fun maybeAutoBlockDangerous(uid: Int, domain: String, pkg: String?) {
        if (!settings.autoBlockDangerous || uid <= 0 || pkg == null) return
        if (!app.container.hosts.isKnownTracker(domain)) return
        if (rules[pkg] == Policy.ALLOW || rules[pkg] == Policy.BLOCK) return
        val set = uidTrackers.getOrPut(uid) {
            java.util.Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
        }
        set.add(domain)
        if (set.size >= dangerTrackerThreshold && autoBlockedUids.add(uid)) {
            scope.launch { app.container.repository.setPolicy(pkg, Policy.BLOCK) }
        }
    }

    private fun startForegroundNotification() {
        NotificationHelper.ensureChannels(this)
        ServiceCompat.startForeground(this, NOTIF_ID, NotificationHelper.serviceNotification(this), 0)
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
        stopTunnel(); scope.cancel(); super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel(); stopForegroundCompat(); stopSelf(); super.onRevoke()
    }

    companion object {
        const val ACTION_START = "com.fusion.firewall.START"
        const val ACTION_STOP = "com.fusion.firewall.STOP"
        private const val NOTIF_ID = 1001

        val isRunning: MutableStateFlow<Boolean> = MutableStateFlow(false)
        val running: StateFlow<Boolean> = isRunning.asStateFlow()

        private fun defaultUpstreams(): List<InetAddress> = runCatching {
            listOf(
                InetAddress.getByName("1.1.1.1"),
                InetAddress.getByName("8.8.8.8"),
                InetAddress.getByName("9.9.9.9"),
            )
        }.getOrDefault(emptyList())

        fun start(context: Context) {
            val intent = Intent(context, FusionVpnService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent)
            else context.startService(intent)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, FusionVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
