package com.fusion.firewall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.fusion.firewall.MainActivity
import com.fusion.firewall.R

/** Builds Fusion's foreground and personal-prompt notifications. */
object NotificationHelper {

    private const val CHANNEL_SERVICE = "fusion_vpn"
    private const val CHANNEL_PROMPT = "fusion_prompt"

    fun ensureChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_SERVICE,
                context.getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW
            )
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_PROMPT,
                context.getString(R.string.notif_prompt_channel_name),
                NotificationManager.IMPORTANCE_HIGH
            )
        )
    }

    fun serviceNotification(context: Context): Notification =
        NotificationCompat.Builder(context, CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_stat_fusion)
            .setContentTitle("Fusion firewall active")
            .setContentText("Monitoring and enforcing network policy")
            .setOngoing(true)
            .setContentIntent(openAppIntent(context))
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()

    fun promptForApp(context: Context, uid: Int, label: String, pkg: String) {
        val allow = ruleAction(context, pkg, "ALLOW", uid * 10 + 1)
        val block = ruleAction(context, pkg, "BLOCK", uid * 10 + 2)
        val notification = NotificationCompat.Builder(context, CHANNEL_PROMPT)
            .setSmallIcon(R.drawable.ic_stat_fusion)
            .setContentTitle("New connection: $label")
            .setContentText("$label is trying to reach the internet. Allow or block permanently?")
            .setAutoCancel(true)
            .setContentIntent(openAppIntent(context))
            .addAction(0, "Allow", allow)
            .addAction(0, "Block", block)
            .build()
        runCatching {
            NotificationManagerCompat.from(context).notify(uid.coerceAtLeast(1), notification)
        }
    }

    private fun openAppIntent(context: Context): PendingIntent {
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        return PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun ruleAction(context: Context, pkg: String, policy: String, requestCode: Int): PendingIntent {
        val intent = Intent(context, RuleActionReceiver::class.java).apply {
            action = RuleActionReceiver.ACTION_SET_POLICY
            putExtra(RuleActionReceiver.EXTRA_PACKAGE, pkg)
            putExtra(RuleActionReceiver.EXTRA_POLICY, policy)
        }
        return PendingIntent.getBroadcast(
            context, requestCode, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
}
