package com.fusion.firewall

import android.app.Application
import com.fusion.firewall.ai.BinaryCoreManager
import com.fusion.firewall.data.RulesRepository
import com.fusion.firewall.net.AppInfoResolver
import com.fusion.firewall.net.HostResolver
import com.fusion.firewall.net.IpIntelProvider
import com.fusion.firewall.net.UsageStatsProvider
import com.fusion.firewall.root.RootMonitor

/** Simple hand-rolled dependency container shared across the app. */
class AppContainer(app: Application) {
    val repository = RulesRepository(app)
    val appInfo = AppInfoResolver(app.packageManager)
    val hosts = HostResolver()
    val binaryCore = BinaryCoreManager(hosts)
    val usageStats = UsageStatsProvider(app)
    val ipIntel = IpIntelProvider(hosts)
    val root = RootMonitor()
}

class FusionApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }
}
