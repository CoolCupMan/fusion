package com.fusion.firewall.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fusion.firewall.ai.AppThreat
import com.fusion.firewall.ai.ThreatAssessment
import com.fusion.firewall.ai.Verdict
import com.fusion.firewall.data.model.AppRule
import com.fusion.firewall.data.model.ConnectionEvent
import com.fusion.firewall.data.model.IpIntel
import com.fusion.firewall.data.model.Policy
import com.fusion.firewall.ui.AppIntelReport
import com.fusion.firewall.ui.DestinationIntel
import com.fusion.firewall.ui.FusionViewModel
import com.fusion.firewall.ui.SectionHeader
import com.fusion.firewall.ui.VerdictBadge

@Composable
fun IntelScreen(viewModel: FusionViewModel, modifier: Modifier = Modifier) {
    val blockedApps by viewModel.blockedApps.collectAsState()
    val reports by viewModel.appReports.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val rootAvailable by viewModel.rootAvailable.collectAsState()
    val rootConnections by viewModel.rootConnections.collectAsState()
    val services by viewModel.systemServices.collectAsState()
    val events by viewModel.events.collectAsState()
    val verdicts by viewModel.assessments.collectAsState()
    val threats by viewModel.appThreats.collectAsState()

    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Intelligence", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            "Ask AI about the apps you blocked, and see where their traffic goes — " +
                "vendor, network route, and approximate (IP-based) location.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
        )

        // Online enrichment toggle
        Card {
            Row(
                Modifier.fillMaxWidth().padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Online intelligence", fontWeight = FontWeight.SemiBold)
                    Text(
                        if (settings.ipIntelEndpoint.isBlank())
                            "Set an endpoint in Settings to fetch geo/entity/ASN data."
                        else "Sends destination IPs to your endpoint for enrichment.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
                    )
                }
                Switch(
                    checked = settings.onlineIntelEnabled,
                    onCheckedChange = { viewModel.setOnlineIntel(it) },
                )
            }
        }

        AppThreatSection(threats, settings.autoBlockDangerous, viewModel)

        RecommendedActions(events, verdicts, viewModel)

        SectionHeader("Manually blocked apps (${blockedApps.size})")
        if (blockedApps.isEmpty()) {
            Text(
                "Block an app in the Apps tab, then ask AI about it here.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            )
        } else {
            blockedApps.forEach { app ->
                BlockedAppCard(app, reports[app.packageName], onAsk = { viewModel.askAiAboutApp(app) })
            }
        }

        RootSection(rootAvailable, rootConnections.size, services.size,
            rootConnections, viewModel)
    }
}

@Composable
private fun BlockedAppCard(
    app: AppRule,
    report: AppIntelReport?,
    onAsk: () -> Unit,
) {
    Card {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(app.label, fontWeight = FontWeight.SemiBold)
                    Text(
                        app.packageName,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    )
                }
                if (report?.loading == true) {
                    CircularProgressIndicator(Modifier.padding(start = 8.dp), strokeWidth = 2.dp)
                } else {
                    OutlinedButton(onClick = onAsk) { Text("Ask AI") }
                }
            }
            if (report != null && !report.loading) {
                Divider(Modifier.padding(vertical = 10.dp))
                Text(report.summary, style = MaterialTheme.typography.bodyMedium)
                report.destinations.forEach { d -> DestinationRow(d) }
            }
        }
    }
}

@Composable
private fun DestinationRow(d: DestinationIntel) {
    Column(Modifier.fillMaxWidth().padding(top = 10.dp)) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "${d.hostname ?: d.ip}:${d.port}",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
            d.assessment?.let { VerdictBadge(it.verdict, it.confidence) }
        }
        Text(
            "${d.transport} · ${d.ip}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
        )
        IntelLine(d.intel)
    }
}

@Composable
private fun RootSection(
    rootAvailable: Boolean?,
    connCount: Int,
    serviceCount: Int,
    connections: List<com.fusion.firewall.root.RootConnection>,
    viewModel: FusionViewModel,
) {
    SectionHeader("Root / deep monitoring")
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            when (rootAvailable) {
                null -> {
                    Text(
                        "Deep monitoring reads the kernel connection table, processes and " +
                            "system services directly — but only if this device is already " +
                            "rooted (Magisk/su). Fusion cannot root or flash the phone itself.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(onClick = { viewModel.refreshRoot() }, modifier = Modifier.padding(top = 10.dp)) {
                        Text("Check for root access")
                    }
                }
                false -> {
                    Text("Root not available.", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.error)
                    Text(
                        "This device is not rooted, so system-daemon-level monitoring is not " +
                            "possible from within an app. Rooting or flashing firmware is a " +
                            "separate, at-your-own-risk process done from a PC — Fusion does not " +
                            "and cannot perform it. VPN monitoring still works without root.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                        modifier = Modifier.padding(top = 4.dp),
                    )
                    OutlinedButton(onClick = { viewModel.refreshRoot() }, modifier = Modifier.padding(top = 8.dp)) {
                        Text("Re-check")
                    }
                }
                true -> {
                    Text("Root available", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
                    Text(
                        "$connCount live connections · $serviceCount services/processes",
                        style = MaterialTheme.typography.labelMedium,
                    )
                    Button(onClick = { viewModel.refreshRoot() }, modifier = Modifier.padding(top = 8.dp)) {
                        Text("Refresh deep snapshot")
                    }
                    connections.take(30).forEach { c ->
                        Divider(Modifier.padding(vertical = 6.dp))
                        Text(
                            "${viewModel.appLabelForUid(c.uid)}  ·  uid ${c.uid}",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            "${c.protocol}  ${c.remoteAddress}:${c.remotePort}  ${c.state}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AppThreatSection(
    threats: List<AppThreat>,
    autoBlock: Boolean,
    viewModel: FusionViewModel,
) {
    SectionHeader("Dangerous app analysis")
    Text(
        "Fusion analyzes each app by the traffic it actually produces — trackers, " +
            "telemetry and malicious endpoints — and flags the dangerous ones.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
    )
    Card {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("Auto-block dangerous apps", fontWeight = FontWeight.SemiBold)
                Text(
                    "Realtime monitoring permanently blocks apps that contact many " +
                        "trackers/malware domains.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
                )
            }
            Switch(checked = autoBlock, onCheckedChange = { viewModel.setAutoBlockDangerous(it) })
        }
    }
    OutlinedButton(onClick = { viewModel.analyzeApps() }, modifier = Modifier.fillMaxWidth()) {
        Text("Re-analyze installed apps")
    }

    val flagged = threats.filter { it.verdict != Verdict.SAFE }
    if (flagged.isEmpty()) {
        Text(
            "No dangerous apps detected yet. Turn on protection and let it run so Fusion " +
                "can observe each app's traffic.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
        )
    } else {
        flagged.forEach { t -> ThreatCard(t, viewModel) }
    }
}

@Composable
private fun ThreatCard(t: AppThreat, viewModel: FusionViewModel) {
    Card {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(t.label, fontWeight = FontWeight.SemiBold)
                    Text(
                        t.packageName + if (t.system) " · system" else "",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    )
                }
                VerdictBadge(t.verdict, t.score / 100f)
            }
            t.reasons.forEach {
                Text("• $it", style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 2.dp))
            }
            Text(
                "${t.totalLookups} domains · ${t.blockedLookups} blocked",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f),
                modifier = Modifier.padding(top = 4.dp),
            )
            Row(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(onClick = { viewModel.setPolicy(t.packageName, Policy.BLOCK) }, label = { Text("Block app") })
                AssistChip(onClick = { viewModel.setPolicy(t.packageName, Policy.ALLOW) }, label = { Text("Allow") })
            }
        }
    }
}

@Composable
private fun RecommendedActions(
    events: List<ConnectionEvent>,
    verdicts: Map<String, ThreatAssessment>,
    viewModel: FusionViewModel,
) {
    val malicious = events.filter { verdicts[it.id]?.verdict == Verdict.MALICIOUS }
    val suspicious = events.filter { verdicts[it.id]?.verdict == Verdict.SUSPICIOUS }
    val trackers = events.filter { it.flagged }

    SectionHeader("Recommended actions")
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        CountPill("Malicious", malicious.size, MaterialTheme.colorScheme.error, Modifier.weight(1f))
        CountPill("Suspicious", suspicious.size, Color(0xFFFFB020), Modifier.weight(1f))
        CountPill("Trackers", trackers.size, MaterialTheme.colorScheme.primary, Modifier.weight(1f))
    }

    val flaggedApps = (malicious + suspicious + trackers).mapNotNull { it.packageName }.distinct()
    Button(
        onClick = { viewModel.blockAllFlagged() },
        enabled = flaggedApps.isNotEmpty(),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            if (flaggedApps.isEmpty()) "Nothing flagged to block"
            else "Block all flagged apps (${flaggedApps.size})"
        )
    }

    val concerning = (malicious + suspicious + trackers).distinctBy { it.id }.take(15)
    if (concerning.isEmpty()) {
        Text(
            "No suspicious, malicious or tracker traffic classified yet. Block an app in the " +
                "Apps tab and let it run — Fusion auto-classifies every attempt it makes.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
        )
    } else {
        concerning.forEach { ev ->
            val verdict = verdicts[ev.id]
            Card {
                Column(Modifier.fillMaxWidth().padding(14.dp)) {
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(ev.appLabel ?: ev.packageName ?: "Unknown", fontWeight = FontWeight.SemiBold)
                            Text(
                                "${ev.hostname ?: ev.remoteIp}:${ev.remotePort} · ${ev.transport}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                            )
                        }
                        verdict?.let { VerdictBadge(it.verdict, it.confidence) }
                    }
                    verdict?.reason?.let {
                        Text(it, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp))
                    }
                    Row(
                        Modifier.fillMaxWidth().padding(top = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        AssistChip(
                            onClick = {
                                viewModel.assess(ev)
                                viewModel.lookupIntel(ev.remoteIp, ev.hostname)
                            },
                            label = { Text("Ask AI") },
                        )
                        ev.packageName?.let { pkg ->
                            AssistChip(
                                onClick = { viewModel.setPolicy(pkg, Policy.BLOCK) },
                                label = { Text("Block app") },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CountPill(label: String, count: Int, accent: Color, modifier: Modifier = Modifier) {
    Card(modifier) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Text("$count", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, color = accent)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        }
    }
}

/** Compact one-line intel view used inside a blocked-app report. */
@Composable
fun IntelLine(intel: IpIntel?) {
    if (intel == null) return
    val parts = buildList {
        intel.locationLine()?.let { add(it) }
        intel.org?.let { add(it) }
        intel.asn?.let { add(it) }
        if (intel.isHosting) add("datacenter")
    }
    if (parts.isNotEmpty()) {
        Text(
            parts.joinToString(" · "),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.secondary,
        )
    }
    intel.coordsLine()?.let {
        Text(
            "≈ $it (IP-based, approximate)",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f),
        )
    }
}
