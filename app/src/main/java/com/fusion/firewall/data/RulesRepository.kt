package com.fusion.firewall.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.fusion.firewall.data.model.Policy
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "fusion_rules")

/**
 * Persists per-app firewall rules and global settings. Rules survive reboots and
 * app updates, so a decision the user makes is permanent until they change it.
 */
class RulesRepository(private val context: Context) {

    private object Keys {
        val RULES = stringPreferencesKey("rules_json")
        val FIREWALL_ENABLED = booleanPreferencesKey("firewall_enabled")
        val DEFAULT_POLICY = stringPreferencesKey("default_policy")
        val PROMPT_NEW = booleanPreferencesKey("prompt_new_apps")
        val AI_MODE = stringPreferencesKey("ai_mode")
        val AI_AUTO = booleanPreferencesKey("ai_auto_apply")
        val BC_ENDPOINT = stringPreferencesKey("bc_endpoint")
        val BC_KEY = stringPreferencesKey("bc_api_key")
        val BLOCK_PENDING = booleanPreferencesKey("block_pending")
        val INTEL_ENDPOINT = stringPreferencesKey("intel_endpoint")
        val INTEL_KEY = stringPreferencesKey("intel_api_key")
        val ONLINE_INTEL = booleanPreferencesKey("online_intel")
        val ROOT_MODE = booleanPreferencesKey("root_mode")
    }

    private val json = Json { ignoreUnknownKeys = true }

    /** Map of package name -> policy for every app the user has decided on. */
    val rules: Flow<Map<String, Policy>> = context.dataStore.data.map { prefs ->
        decodeRules(prefs[Keys.RULES])
    }

    val settings: Flow<FusionSettings> = context.dataStore.data.map { prefs ->
        FusionSettings(
            firewallEnabled = prefs[Keys.FIREWALL_ENABLED] ?: false,
            defaultPolicy = Policy.fromName(prefs[Keys.DEFAULT_POLICY]),
            promptOnNewApps = prefs[Keys.PROMPT_NEW] ?: true,
            aiMode = AiMode.fromName(prefs[Keys.AI_MODE]),
            aiAutoApply = prefs[Keys.AI_AUTO] ?: false,
            binaryCoreEndpoint = prefs[Keys.BC_ENDPOINT] ?: "",
            binaryCoreApiKey = prefs[Keys.BC_KEY] ?: "",
            blockPendingByDefault = prefs[Keys.BLOCK_PENDING] ?: true,
            ipIntelEndpoint = prefs[Keys.INTEL_ENDPOINT] ?: "",
            ipIntelApiKey = prefs[Keys.INTEL_KEY] ?: "",
            onlineIntelEnabled = prefs[Keys.ONLINE_INTEL] ?: false,
            rootModeEnabled = prefs[Keys.ROOT_MODE] ?: false,
        )
    }

    private fun decodeRules(raw: String?): Map<String, Policy> {
        if (raw.isNullOrBlank()) return emptyMap()
        return runCatching {
            json.decodeFromString<Map<String, String>>(raw)
                .mapValues { Policy.fromName(it.value) }
        }.getOrDefault(emptyMap())
    }

    suspend fun setPolicy(packageName: String, policy: Policy) {
        context.dataStore.edit { prefs ->
            val current = decodeRules(prefs[Keys.RULES]).toMutableMap()
            if (policy == Policy.PENDING) current.remove(packageName) else current[packageName] = policy
            prefs[Keys.RULES] = json.encodeToString(
                current.mapValues { it.value.name }
            )
        }
    }

    suspend fun setPolicies(updates: Map<String, Policy>) {
        context.dataStore.edit { prefs ->
            val current = decodeRules(prefs[Keys.RULES]).toMutableMap()
            updates.forEach { (pkg, policy) ->
                if (policy == Policy.PENDING) current.remove(pkg) else current[pkg] = policy
            }
            prefs[Keys.RULES] = json.encodeToString(current.mapValues { it.value.name })
        }
    }

    suspend fun setFirewallEnabled(enabled: Boolean) =
        context.dataStore.edit { it[Keys.FIREWALL_ENABLED] = enabled }

    suspend fun setDefaultPolicy(policy: Policy) =
        context.dataStore.edit { it[Keys.DEFAULT_POLICY] = policy.name }

    suspend fun setPromptOnNewApps(value: Boolean) =
        context.dataStore.edit { it[Keys.PROMPT_NEW] = value }

    suspend fun setAiMode(mode: AiMode) =
        context.dataStore.edit { it[Keys.AI_MODE] = mode.name }

    suspend fun setAiAutoApply(value: Boolean) =
        context.dataStore.edit { it[Keys.AI_AUTO] = value }

    suspend fun setBinaryCoreEndpoint(value: String) =
        context.dataStore.edit { it[Keys.BC_ENDPOINT] = value }

    suspend fun setBinaryCoreApiKey(value: String) =
        context.dataStore.edit { it[Keys.BC_KEY] = value }

    suspend fun setBlockPending(value: Boolean) =
        context.dataStore.edit { it[Keys.BLOCK_PENDING] = value }

    suspend fun setIpIntelEndpoint(value: String) =
        context.dataStore.edit { it[Keys.INTEL_ENDPOINT] = value }

    suspend fun setIpIntelApiKey(value: String) =
        context.dataStore.edit { it[Keys.INTEL_KEY] = value }

    suspend fun setOnlineIntel(value: Boolean) =
        context.dataStore.edit { it[Keys.ONLINE_INTEL] = value }

    suspend fun setRootMode(value: Boolean) =
        context.dataStore.edit { it[Keys.ROOT_MODE] = value }
}
