package com.fusion.firewall.vpn

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView

/**
 * A tiny "draw over other apps" bubble that pops up the instant Fusion blocks an
 * app's traffic. Collapsed it is a small circular shield; tapping it expands a
 * compact menu — Unblock, Keep blocked, Open Fusion — so the user can react
 * without leaving the app they are in. Auto-hides after a few seconds.
 *
 * All window operations run on the main thread. Showing requires the
 * SYSTEM_ALERT_WINDOW ("draw over other apps") permission; callers must check
 * [canShow] first.
 */
class BlockOverlay(private val context: Context) {

    private val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val main = Handler(Looper.getMainLooper())

    private var root: LinearLayout? = null
    private var titleView: TextView? = null
    private var subView: TextView? = null
    private var menu: LinearLayout? = null
    private var expanded = false
    private var blockedCount = 0

    // Callbacks set per shown event.
    private var onUnblock: (() -> Unit)? = null
    private var onOpen: (() -> Unit)? = null

    private val hideRunnable = Runnable { hide() }

    private fun dp(v: Int): Int = (v * context.resources.displayMetrics.density).toInt()

    companion object {
        fun canShow(context: Context): Boolean =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(context)
    }

    /** Show (or update) the bubble for a freshly blocked connection. */
    fun show(appLabel: String, domain: String?, unblock: () -> Unit, open: () -> Unit) {
        main.post {
            onUnblock = unblock
            onOpen = open
            blockedCount++
            if (root == null) runCatching { build() }
            titleView?.text = "Blocked" + if (blockedCount > 1) "  ·  $blockedCount" else ""
            subView?.text = buildString {
                append(appLabel)
                if (!domain.isNullOrBlank()) append("  →  ").append(domain)
            }
            // Re-arm auto-hide. If the user already expanded it, give them longer.
            main.removeCallbacks(hideRunnable)
            main.postDelayed(hideRunnable, if (expanded) 9000L else 6000L)
        }
    }

    fun hide() {
        main.post {
            main.removeCallbacks(hideRunnable)
            root?.let { r -> runCatching { wm.removeView(r) } }
            root = null; menu = null; titleView = null; subView = null
            expanded = false; blockedCount = 0
        }
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun build() {
        val accent = Color.parseColor("#3DDC97")
        val danger = Color.parseColor("#FF5C6C")
        val surface = Color.parseColor("#141B24")
        val onSurface = Color.parseColor("#E6EDF3")

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(8), dp(8), dp(8), dp(8))
            background = GradientDrawable().apply {
                cornerRadius = dp(22).toFloat()
                setColor(surface)
                setStroke(dp(1), accent)
            }
            elevation = dp(8).toFloat()
        }

        // Tiny circular shield badge (always visible).
        val badge = TextView(context).apply {
            text = "🛡"
            textSize = 16f
            gravity = Gravity.CENTER
            setTextColor(onSurface)
            val size = dp(32)
            layoutParams = LinearLayout.LayoutParams(size, size)
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(danger)
            }
            setOnClickListener { toggle() }
        }
        container.addView(badge)

        // Expandable menu (hidden until the badge is tapped).
        val menuLayout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), dp(2), dp(4), dp(2))
            visibility = View.GONE
        }
        val title = TextView(context).apply {
            text = "Blocked"
            setTextColor(danger)
            textSize = 13f
        }
        val sub = TextView(context).apply {
            setTextColor(onSurface)
            textSize = 12f
            maxWidth = dp(220)
            maxLines = 2
        }
        val buttons = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(6), 0, 0)
        }
        buttons.addView(pill("Unblock", accent) { onUnblock?.invoke(); hide() })
        buttons.addView(pill("Keep", onSurface) { hide() })
        buttons.addView(pill("Open", accent) { onOpen?.invoke(); hide() })

        menuLayout.addView(title)
        menuLayout.addView(sub)
        menuLayout.addView(buttons)
        container.addView(menuLayout)

        val type =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            else
                @Suppress("DEPRECATION") WindowManager.LayoutParams.TYPE_PHONE

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            android.graphics.PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP or Gravity.END
            x = dp(10)
            y = dp(90)
        }

        wm.addView(container, params)
        root = container
        menu = menuLayout
        titleView = title
        subView = sub
        expanded = false
    }

    private fun toggle() {
        expanded = !expanded
        menu?.visibility = if (expanded) View.VISIBLE else View.GONE
        main.removeCallbacks(hideRunnable)
        main.postDelayed(hideRunnable, if (expanded) 9000L else 6000L)
    }

    private fun pill(label: String, color: Int, onClick: () -> Unit): TextView =
        TextView(context).apply {
            text = label
            setTextColor(color)
            textSize = 12f
            setPadding(dp(10), dp(6), dp(10), dp(6))
            background = GradientDrawable().apply {
                cornerRadius = dp(14).toFloat()
                setColor(Color.parseColor("#1E2833"))
            }
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            lp.marginEnd = dp(6)
            layoutParams = lp
            setOnClickListener { onClick() }
        }
}
