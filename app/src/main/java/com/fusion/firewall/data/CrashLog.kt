package com.fusion.firewall.data

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import com.fusion.firewall.BuildConfig
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Captures uncaught exceptions to a file so a startup crash is diagnosable
 * without a USB cable: the trace is saved in app storage (read back on the next
 * launch to show an on-screen report instead of closing instantly) and mirrored
 * to Download/Fusion so any file manager can open and share it.
 */
object CrashLog {

    private const val FILE = "last_crash.txt"

    fun save(context: Context, throwable: Throwable) {
        val text = buildString {
            appendLine("Fusion crash report")
            appendLine(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date()))
            appendLine("App: ${BuildConfig.APPLICATION_ID}  v${BuildConfig.VERSION_NAME}")
            appendLine(
                "Device: ${Build.MANUFACTURER} ${Build.MODEL} · Android " +
                    "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
            )
            appendLine()
            appendLine(Log.getStackTraceString(throwable))
        }
        runCatching { File(context.filesDir, FILE).writeText(text) }
        runCatching { exportToDownloads(context, text) }
    }

    /** The saved crash trace, or null if the last run exited cleanly. */
    fun read(context: Context): String? = runCatching {
        File(context.filesDir, FILE).takeIf { it.exists() }?.readText()
    }.getOrNull()

    fun clear(context: Context) {
        runCatching { File(context.filesDir, FILE).delete() }
    }

    /** Mirror the trace to Download/Fusion/fusion-crash.txt for file managers. */
    fun exportToDownloads(context: Context, text: String): String? = runCatching {
        val name = "fusion-crash.txt"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/Fusion")
            }
            val resolver = context.contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return@runCatching null
            resolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
            "Download/Fusion/$name"
        } else {
            @Suppress("DEPRECATION")
            val base = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val dir = File(base, "Fusion").apply { mkdirs() }
            File(dir, name).apply { writeText(text) }.absolutePath
        }
    }.getOrNull()
}
