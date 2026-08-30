package com.fusion.firewall.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

/** Metadata for one imported block list. Domains live in a file, not here. */
@Serializable
data class BlockListMeta(
    val id: String,
    val name: String,
    val source: String,
    val enabled: Boolean,
    val count: Int,
)

private val Context.blockListStore: DataStore<Preferences> by preferencesDataStore(name = "fusion_blocklists")

/**
 * Persists the user's block lists, custom blocked domains, and whitelist. List
 * domains are stored one-per-line in files under filesDir/blocklists so very
 * large lists (hosts files with 100k+ entries) don't bloat preferences.
 */
class BlockListRepository(private val context: Context) {

    private object Keys {
        val LISTS = stringPreferencesKey("lists_json")
        val CUSTOM = stringPreferencesKey("custom_json")
        val WHITELIST = stringPreferencesKey("whitelist_json")
    }

    private val json = Json { ignoreUnknownKeys = true }
    private val dir: File get() = File(context.filesDir, "blocklists").apply { mkdirs() }

    val lists: Flow<List<BlockListMeta>> = context.blockListStore.data.map { decodeLists(it[Keys.LISTS]) }
    val custom: Flow<Set<String>> = context.blockListStore.data.map { decodeSet(it[Keys.CUSTOM]) }
    val whitelist: Flow<Set<String>> = context.blockListStore.data.map { decodeSet(it[Keys.WHITELIST]) }

    private fun decodeLists(raw: String?): List<BlockListMeta> =
        if (raw.isNullOrBlank()) emptyList()
        else runCatching { json.decodeFromString<List<BlockListMeta>>(raw) }.getOrDefault(emptyList())

    private fun decodeSet(raw: String?): Set<String> =
        if (raw.isNullOrBlank()) emptySet()
        else runCatching { json.decodeFromString<Set<String>>(raw) }.getOrDefault(emptySet())

    /** All domains that are currently active: custom entries + enabled lists. */
    suspend fun activeDomains(): Set<String> = withContext(Dispatchers.IO) {
        val prefs = context.blockListStore.data.first()
        val result = HashSet<String>(decodeSet(prefs[Keys.CUSTOM]))
        for (meta in decodeLists(prefs[Keys.LISTS])) {
            if (!meta.enabled) continue
            result += readListFile(meta.id)
        }
        result
    }

    private fun readListFile(id: String): Set<String> =
        runCatching { File(dir, "$id.txt").readLines().toSet() }.getOrDefault(emptySet())

    suspend fun addCustom(domain: String) = mutateSet(Keys.CUSTOM) { it + normalize(domain) }
    suspend fun removeCustom(domain: String) = mutateSet(Keys.CUSTOM) { it - normalize(domain) }
    suspend fun addWhitelist(domain: String) = mutateSet(Keys.WHITELIST) { it + normalize(domain) }
    suspend fun removeWhitelist(domain: String) = mutateSet(Keys.WHITELIST) { it - normalize(domain) }

    private suspend fun mutateSet(key: Preferences.Key<String>, transform: (Set<String>) -> Set<String>) {
        context.blockListStore.edit { prefs ->
            val current = decodeSet(prefs[key])
            prefs[key] = json.encodeToString(transform(current).filter { it.isNotBlank() }.toSet())
        }
    }

    /** Store a freshly parsed list to a file and register its metadata. */
    suspend fun importList(name: String, source: String, domains: Set<String>) = withContext(Dispatchers.IO) {
        val id = UUID.randomUUID().toString().take(8)
        File(dir, "$id.txt").writeText(domains.joinToString("\n"))
        context.blockListStore.edit { prefs ->
            val current = decodeLists(prefs[Keys.LISTS]).toMutableList()
            current += BlockListMeta(id, name, source, enabled = true, count = domains.size)
            prefs[Keys.LISTS] = json.encodeToString(current)
        }
    }

    suspend fun setEnabled(id: String, enabled: Boolean) {
        context.blockListStore.edit { prefs ->
            val current = decodeLists(prefs[Keys.LISTS]).map {
                if (it.id == id) it.copy(enabled = enabled) else it
            }
            prefs[Keys.LISTS] = json.encodeToString(current)
        }
    }

    suspend fun removeList(id: String) {
        runCatching { File(dir, "$id.txt").delete() }
        context.blockListStore.edit { prefs ->
            val current = decodeLists(prefs[Keys.LISTS]).filterNot { it.id == id }
            prefs[Keys.LISTS] = json.encodeToString(current)
        }
    }

    private fun normalize(domain: String): String =
        domain.trim().lowercase().removePrefix("*.").trimEnd('.')
}
