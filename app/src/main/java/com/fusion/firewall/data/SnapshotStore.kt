package com.fusion.firewall.data

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * One saved set of instructions: the user's block/allow decisions plus the live
 * blocked/allowed traffic at the moment of saving. Serialized to JSON both in
 * fast internal storage (for instant reload) and to shared phone storage (so a
 * standard Android file manager — Files, BD File Manager, Dateimanager+, Amaze —
 * can see and copy it).
 */
@Serializable
data class FusionSnapshot(
    val savedAt: Long,
    val appVersion: String = "",
    val blockedApps: List<String> = emptyList(),
    val allowedApps: List<String> = emptyList(),
    val customBlockedDomains: List<String> = emptyList(),
    val whitelistDomains: List<String> = emptyList(),
    val importedLists: List<BlockListMeta> = emptyList(),
    val trafficBlocked: List<String> = emptyList(),
    val trafficAllowed: List<String> = emptyList(),
    val droppedCount: Long = 0,
    val allowedCount: Long = 0,
)

/** Lightweight row for the storage manager UI. */
data class SnapshotMeta(
    val savedAt: Long,
    val fileName: String,
    val blockedApps: Int,
    val blockedDomains: Int,
    val allowedDomains: Int,
) {
    val label: String get() = fmt.format(Date(savedAt))

    companion object {
        private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    }
}

/**
 * Saves and restores [FusionSnapshot]s. Internal copies live under
 * filesDir/snapshots for fast listing and reload; every save is also mirrored to
 * the public Download/Fusion folder so external file managers can reach it.
 */
class SnapshotStore(private val context: Context) {

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }
    private val dir: File get() = File(context.filesDir, "snapshots").apply { mkdirs() }

    private fun fileName(savedAt: Long): String = "fusion-snapshot-$savedAt.json"

    /** Persist a snapshot internally; returns the file it was written to. */
    suspend fun saveInternal(snapshot: FusionSnapshot): File = withContext(Dispatchers.IO) {
        val f = File(dir, fileName(snapshot.savedAt))
        f.writeText(json.encodeToString(snapshot))
        f
    }

    /** All saved snapshots, newest first. */
    suspend fun list(): List<SnapshotMeta> = withContext(Dispatchers.IO) {
        (dir.listFiles { f -> f.extension == "json" } ?: emptyArray())
            .mapNotNull { f -> parse(f.readTextOrNull())?.let { it to f.name } }
            .map { (s, name) ->
                SnapshotMeta(s.savedAt, name, s.blockedApps.size, s.customBlockedDomains.size, s.whitelistDomains.size)
            }
            .sortedByDescending { it.savedAt }
    }

    suspend fun load(fileName: String): FusionSnapshot? = withContext(Dispatchers.IO) {
        parse(File(dir, fileName).readTextOrNull())
    }

    /** The most recently saved snapshot, or null if none exist. */
    suspend fun latest(): FusionSnapshot? = withContext(Dispatchers.IO) {
        (dir.listFiles { f -> f.extension == "json" } ?: emptyArray())
            .mapNotNull { parse(it.readTextOrNull()) }
            .maxByOrNull { it.savedAt }
    }

    suspend fun delete(fileName: String) = withContext(Dispatchers.IO) {
        runCatching { File(dir, fileName).delete() }
        Unit
    }

    /** Parse a snapshot from an arbitrary JSON string (e.g. a file the user picked). */
    fun parse(raw: String?): FusionSnapshot? {
        if (raw.isNullOrBlank()) return null
        return runCatching { json.decodeFromString<FusionSnapshot>(raw) }.getOrNull()
    }

    fun toJson(snapshot: FusionSnapshot): String = json.encodeToString(snapshot)

    /** Read a snapshot the user picked with a file manager (content:// or file://). */
    suspend fun readUri(uri: Uri): FusionSnapshot? = withContext(Dispatchers.IO) {
        val text = runCatching {
            context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        }.getOrNull()
        parse(text)
    }

    /**
     * Mirror a snapshot to shared storage so any file manager can see it. Uses
     * MediaStore Downloads on API 29+ (no permission needed) and the public
     * Download folder on older devices (needs WRITE_EXTERNAL_STORAGE ≤ API 28).
     * Returns a human-readable location for the UI, or null on failure.
     */
    suspend fun exportToPhoneStorage(snapshot: FusionSnapshot): String? = withContext(Dispatchers.IO) {
        val name = fileName(snapshot.savedAt)
        val payload = json.encodeToString(snapshot)
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/json")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/Fusion")
                }
                val resolver = context.contentResolver
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: return@runCatching null
                resolver.openOutputStream(uri)?.use { it.write(payload.toByteArray()) }
                "Download/Fusion/$name"
            } else {
                @Suppress("DEPRECATION")
                val base = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                val target = File(base, "Fusion").apply { mkdirs() }
                val f = File(target, name)
                f.writeText(payload)
                f.absolutePath
            }
        }.getOrNull()
    }

    private fun File.readTextOrNull(): String? = runCatching { readText() }.getOrNull()
}
