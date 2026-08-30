package com.fusion.firewall.root

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader

/** A socket read from the kernel connection table via root. */
data class RootConnection(
    val protocol: String,
    val localAddress: String,
    val localPort: Int,
    val remoteAddress: String,
    val remotePort: Int,
    val uid: Int,
    val state: String,
)

/**
 * Optional deep-monitoring layer. Fusion CANNOT root or flash the device — this
 * only does anything when the device is *already* rooted (Magisk/su). With root
 * it reads the kernel connection table and process/service lists directly, so it
 * sees every connection (including allowed apps) without a VPN. All commands are
 * read-only.
 */
class RootMonitor {

    @Volatile private var rootChecked = false
    @Volatile private var rootAvailable = false

    suspend fun isRootAvailable(): Boolean = withContext(Dispatchers.IO) {
        if (rootChecked) return@withContext rootAvailable
        rootAvailable = runCatching {
            val out = exec("id") ?: return@runCatching false
            out.contains("uid=0")
        }.getOrDefault(false)
        rootChecked = true
        rootAvailable
    }

    /** Run a single command as root, returning combined stdout (or null on failure). */
    private fun exec(command: String): String? = runCatching {
        val process = ProcessBuilder("su").redirectErrorStream(true).start()
        DataOutputStream(process.outputStream).use { os ->
            os.writeBytes("$command\n")
            os.writeBytes("exit\n")
            os.flush()
        }
        val text = BufferedReader(InputStreamReader(process.inputStream)).use { it.readText() }
        process.waitFor()
        text
    }.getOrNull()

    suspend fun connections(): List<RootConnection> = withContext(Dispatchers.IO) {
        if (!isRootAvailable()) return@withContext emptyList()
        val out = ArrayList<RootConnection>()
        listOf("tcp" to "/proc/net/tcp", "tcp6" to "/proc/net/tcp6",
            "udp" to "/proc/net/udp", "udp6" to "/proc/net/udp6").forEach { (proto, path) ->
            val text = exec("cat $path") ?: return@forEach
            parseProcNet(proto, text, out)
        }
        out
    }

    suspend fun services(): List<String> = withContext(Dispatchers.IO) {
        if (!isRootAvailable()) return@withContext emptyList()
        val text = exec("service list") ?: exec("ps -A") ?: return@withContext emptyList()
        text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.take(400).toList()
    }

    private fun parseProcNet(proto: String, text: String, out: MutableList<RootConnection>) {
        val lines = text.lineSequence().drop(1) // header
        for (line in lines) {
            val f = line.trim().split(Regex("\\s+"))
            if (f.size < 8) continue
            val local = f[1].split(':')
            val rem = f[2].split(':')
            if (local.size < 2 || rem.size < 2) continue
            val uid = f[7].toIntOrNull() ?: -1
            val remoteIp = hexToIp(rem[0])
            val remotePort = rem[1].toIntOrNull(16) ?: 0
            if (remotePort == 0) continue // listeners / no peer
            out.add(
                RootConnection(
                    protocol = proto,
                    localAddress = hexToIp(local[0]),
                    localPort = local[1].toIntOrNull(16) ?: 0,
                    remoteAddress = remoteIp,
                    remotePort = remotePort,
                    uid = uid,
                    state = tcpState(f[3]),
                )
            )
        }
    }

    private fun hexToIp(hex: String): String = runCatching {
        when (hex.length) {
            8 -> { // IPv4, little-endian
                val b = (0 until 4).map { hex.substring(it * 2, it * 2 + 2).toInt(16) }
                "${b[3]}.${b[2]}.${b[1]}.${b[0]}"
            }
            32 -> { // IPv6 — group into 8 hextets (endianness best-effort)
                (0 until 8).joinToString(":") { hex.substring(it * 4, it * 4 + 4) }
            }
            else -> hex
        }
    }.getOrDefault(hex)

    private fun tcpState(hex: String): String = when (hex.uppercase()) {
        "01" -> "ESTABLISHED"; "02" -> "SYN_SENT"; "03" -> "SYN_RECV"
        "04" -> "FIN_WAIT1"; "05" -> "FIN_WAIT2"; "06" -> "TIME_WAIT"
        "07" -> "CLOSE"; "08" -> "CLOSE_WAIT"; "0A" -> "LISTEN"; else -> "—"
    }
}
