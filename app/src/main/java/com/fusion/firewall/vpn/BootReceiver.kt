package com.fusion.firewall.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.fusion.firewall.FusionApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Re-arms the firewall after a reboot or app update, but only if the user had it
 * enabled and has already granted VPN consent (prepare() returns null). Any
 * platform restriction on background starts is swallowed.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) return

        val app = context.applicationContext as FusionApp
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val enabled = app.container.repository.settings.first().firewallEnabled
                if (enabled && VpnService.prepare(context) == null) {
                    runCatching { FusionVpnService.start(context) }
                }
            } finally {
                pending.finish()
            }
        }
    }
}
