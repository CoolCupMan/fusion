# Fusion

**Fusion** is an Android firewall and realtime traffic monitor. It gives you a
friendly GUI to *see every unconfirmed connection your apps make in realtime*
and to *permanently allow or block* the inbound/outbound traffic of any app or
service — with on-device and API-backed intelligence (**BinaryCore**) that
recommends what to do.

It works on stock, **non-rooted** Android by running a local `VpnService`
(the same technique used by well-known firewalls such as NetGuard and
TrackerControl). Your traffic never leaves the device: captured packets are
inspected on-device and dropped.

---

## What it does

| Capability | How |
|---|---|
| **Visualize unconfirmed traffic in realtime** | Every app you haven't permanently allowed is routed into a local tunnel. Fusion parses each IP/TCP/UDP packet, attributes it to the owning app (`getConnectionOwnerUid`), reads the destination and any DNS query name, and streams it to the live **Traffic** screen. |
| **Permanently allow / block per app** | Each app has a rule: **Allow** (bypasses the tunnel → normal internet), **Block** (routed in and dropped → no internet), or **Ask** (pending your decision). Rules persist across reboots and updates. |
| **Personal prompts for new apps** | The first time an unconfirmed app connects, Fusion raises a notification with **Allow** / **Block** actions. |
| **BinaryCore intelligence** | A local offline engine scores each connection (known trackers, unusual ports, high-entropy/DGA domains, cleartext HTTP) and recommends allow/block. Optionally consult a remote BinaryCore API. Auto-apply and one-tap "triage all pending" are supported. |
| **Per-app data usage** | Via `NetworkStatsManager` (needs Usage Access) the Apps screen shows 24 h data totals and sorts by heaviest talkers. |
| **Legacy → upcoming compatibility** | `minSdk 26` (Android 8) through `targetSdk 34` (Android 14). Both IPv4 and IPv6 are governed. API-gated features (UID attribution, special-use FGS) degrade gracefully on older releases. |
| **Parallel / future installs** | Product-flavor "slots" produce distinct application IDs so multiple Fusion builds can be installed side by side (see below). |

## Screens

- **Dashboard** — one-tap protection toggle, live counters (blocked / pending / flagged), latest flagged connections, and "auto-triage".
- **Traffic** — realtime connection feed with All / Flagged / Pending filters and per-row *Ask BinaryCore / Allow / Block* actions.
- **Apps** — every internet-capable app with an Allow / Block / Ask selector and data usage.
- **BinaryCore** — engine selection (Local / Remote / Hybrid), auto-apply, and recent verdicts.
- **Settings** — default policy for unconfirmed apps, prompts, BinaryCore API endpoint/key, usage-access, and app info.

---

## Building `fusion.apk`

You need the Android SDK. Two ways:

### 1. GitHub Actions (produces the APK for you)

Every push runs [`.github/workflows/android-build.yml`](.github/workflows/android-build.yml),
which builds all slots and uploads them as a **`fusion-apks`** artifact
(`fusion.apk`, `fusion-slotb.apk`, `fusion-slotc.apk`). Download it from the
run's *Artifacts* section. Pushing a `v*` tag additionally publishes a GitHub
Release with the APKs attached.

### 2. Locally

```bash
# Android SDK required (ANDROID_HOME / sdkmanager). Then:
./gradlew assembleDebug          # builds every slot
# primary APK:
#   app/build/outputs/apk/slotA/debug/app-slotA-debug.apk  -> install as fusion.apk
```

Install: `adb install -r app/build/outputs/apk/slotA/debug/app-slotA-debug.apk`
(or copy any built APK to the phone and open it to sideload).

> The CI builds **debug-signed** APKs so they are directly installable. For a
> Play/production build, add a signing config and run `assembleRelease`.

---

## Parallel & future versions (unique app IDs)

The base application ID is `com.fusion.firewall`. Three **slots** each append a
suffix and a distinct launcher label, so several Fusion builds coexist:

| Slot | Application ID | Label | Output |
|---|---|---|---|
| A (primary) | `com.fusion.firewall.slota` | Fusion | `fusion.apk` |
| B | `com.fusion.firewall.slotb` | Fusion B | `fusion-slotb.apk` |
| C | `com.fusion.firewall.slotc` | Fusion C | `fusion-slotc.apk` |

Because Android keys installs by application ID, slot A / B / C install in
parallel and never overwrite each other — handy for running a stable build
alongside a test of a future version. Add more slots in
[`app/build.gradle.kts`](app/build.gradle.kts) as needed.

---

## BinaryCore integration

BinaryCore has two engines behind one interface
([`BinaryCoreEngine`](app/src/main/java/com/fusion/firewall/ai/BinaryCore.kt)):

- **Local** (`LocalBinaryCoreEngine`) — fully offline heuristics. No account, no
  network. This is the default.
- **Remote** (`RemoteBinaryCoreClient`) — calls a BinaryCore API you configure
  in **Settings** (endpoint URL + API key). Nothing is hard-coded, so it works
  against whichever BinaryCore deployment you point it at.

**Hybrid** mode runs the local engine first and only calls the API to confirm
low-confidence verdicts.

### Remote API contract

`POST <endpoint>` with `Authorization: Bearer <key>` and JSON body:

```json
{
  "app": "Example",
  "package": "com.example.app",
  "system": false,
  "host": "telemetry.example.com",
  "ip": "203.0.113.5",
  "port": 443,
  "transport": "TCP"
}
```

Expected JSON response:

```json
{
  "verdict": "SUSPICIOUS",
  "confidence": 0.82,
  "reason": "Known telemetry endpoint",
  "recommended_policy": "BLOCK"
}
```

`verdict` ∈ `SAFE|SUSPICIOUS|MALICIOUS|UNKNOWN`;
`recommended_policy` ∈ `ALLOW|BLOCK|PENDING`.

---

## How enforcement works (and its limits)

Fusion does **not** ship a userspace TCP/IP stack. Instead it uses the VPN's
per-app routing:

- **Allowed** apps are added via `addDisallowedApplication`, so they bypass the
  tunnel entirely and get full, unmodified connectivity. (They are therefore
  not packet-inspected — their usage is shown via `NetworkStatsManager`.)
- **Blocked** and **pending** apps are routed into the tunnel; their packets are
  read for the live view and then dropped, which cleanly denies connectivity.

This is robust and battery-friendly, and it is exactly the traffic you care
about visualizing: the *unconfirmed* flows. The trade-off is that Fusion shows
attempted connections and DNS lookups for governed apps rather than full
bidirectional payloads.

Requires the user to grant VPN consent (system dialog) and, optionally, Usage
Access and notification permission.

## Permissions

`INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE(_SPECIAL_USE)`,
`POST_NOTIFICATIONS`, `RECEIVE_BOOT_COMPLETED`, `QUERY_ALL_PACKAGES` (to list
apps), and `PACKAGE_USAGE_STATS` (special access, granted from system settings).

## Project layout

```
app/src/main/java/com/fusion/firewall/
  ai/     BinaryCore engines (local heuristics + remote client) and manager
  data/   DataStore rules/settings, realtime ConnectionLog, models
  net/    app/uid resolver, host reputation, usage stats
  ui/     Compose screens, view model, theme, components
  vpn/    FusionVpnService, packet parser, notifications, receivers
```

## Disclaimer

Fusion is a defensive tool for controlling **your own device's** traffic. Use it
in line with local law and the policies of networks you connect to.
