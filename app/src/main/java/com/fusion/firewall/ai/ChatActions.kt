package com.fusion.firewall.ai

import org.json.JSONObject

/** An action the assistant asked Fusion to perform on the user's behalf. */
data class ChatAction(val action: String, val target: String?)

/**
 * Parses assistant replies for action directives. The model is instructed to
 * append lines of the exact form:
 *   @@FUSION {"action":"block_app","target":"WhatsApp"}
 * one per change. This provider-agnostic protocol lets the chat actually block
 * apps/domains when asked, instead of only describing what to do.
 */
object ChatActions {

    private const val PREFIX = "@@FUSION"

    /** Returns the reply with directive lines removed, plus the parsed actions. */
    fun parse(reply: String): Pair<String, List<ChatAction>> {
        val actions = ArrayList<ChatAction>()
        val kept = StringBuilder()
        for (line in reply.lineSequence()) {
            val t = line.trim()
            if (t.startsWith(PREFIX)) {
                val json = t.removePrefix(PREFIX).trim().removePrefix(":").trim()
                runCatching {
                    val o = JSONObject(json)
                    val action = o.optString("action").trim()
                    if (action.isNotEmpty()) {
                        actions.add(ChatAction(action, o.optString("target").takeIf { it.isNotBlank() }))
                    }
                }
            } else {
                kept.appendLine(line)
            }
        }
        return kept.toString().trim() to actions
    }
}
