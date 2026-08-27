package com.fusion.firewall.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationManagerCompat
import com.fusion.firewall.FusionApp
import com.fusion.firewall.data.model.Policy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** Handles the Allow/Block actions from a personal-prompt notification. */
class RuleActionReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_SET_POLICY) return
        val pkg = intent.getStringExtra(EXTRA_PACKAGE) ?: return
        val policy = Policy.fromName(intent.getStringExtra(EXTRA_POLICY))
        val app = context.applicationContext as FusionApp
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                app.container.repository.setPolicy(pkg, policy)
            } finally {
                runCatching { NotificationManagerCompat.from(context).cancelAll() }
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_SET_POLICY = "com.fusion.firewall.SET_POLICY"
        const val EXTRA_PACKAGE = "package"
        const val EXTRA_POLICY = "policy"
    }
}
