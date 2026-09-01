package com.fusion.firewall

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.Composable
import androidx.core.content.ContextCompat
import com.fusion.firewall.ui.FusionRoot
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.theme.FusionTheme
import com.fusion.firewall.vpn.FusionVpnService

class MainActivity : ComponentActivity() {

    private val viewModel: FusionViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        maybeRequestNotifications()

        setContent {
            FusionTheme {
                FusionScreen(viewModel)
            }
        }
    }

    @Composable
    private fun FusionScreen(viewModel: FusionViewModel) {
        val consentLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == RESULT_OK) FusionVpnService.start(this)
        }
        val importLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocument()
        ) { uri -> if (uri != null) viewModel.importSnapshot(uri) }

        FusionRoot(
            viewModel = viewModel,
            onToggleFirewall = { enable ->
                if (enable) {
                    val prepare = VpnService.prepare(this)
                    if (prepare != null) consentLauncher.launch(prepare)
                    else FusionVpnService.start(this)
                } else {
                    FusionVpnService.stop(this)
                }
            },
            onOpenUsageAccessSettings = {
                runCatching {
                    startActivity(Intent(android.provider.Settings.ACTION_USAGE_ACCESS_SETTINGS))
                }
            },
            onImportSnapshot = {
                runCatching { importLauncher.launch(arrayOf("application/json", "text/plain", "*/*")) }
            },
            onRestartApp = { restartApp() },
        )
    }

    /**
     * Cold-restart Fusion as if launched from scratch after a reboot: stop the
     * tunnel, wipe the live drop log so counters start at zero, then relaunch the
     * launcher activity in a fresh task and kill this process so
     * [FusionApp.onCreate] re-initializes everything from first boot.
     */
    private fun restartApp() {
        runCatching { FusionVpnService.stop(this) }
        com.fusion.firewall.data.ConnectionLog.clear()
        val intent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        runCatching { startActivity(intent) }
        finishAffinity()
        Runtime.getRuntime().exit(0)
    }

    private fun maybeRequestNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED
        ) return
        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 42)
    }
}
