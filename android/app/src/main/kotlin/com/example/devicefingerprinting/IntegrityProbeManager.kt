package com.example.devicefingerprinting

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.annotation.SuppressLint
import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.location.Location
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.os.SystemClock
import android.provider.Settings
import android.view.Display
import android.view.WindowManager
import android.view.accessibility.AccessibilityManager
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.MessageDigest
import java.util.Collections
import java.util.Locale
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.function.Consumer
import org.json.JSONObject

/**
 * Local integrity measurement collector.
 *
 * IMPORTANT: these measurements are risk signals, not remote attestation. On a
 * fully compromised OS an attacker may be able to lie about local state. The
 * server must therefore score these signals together with server-observed
 * device/account behavior and must never trust a client-provided score.
 */
class IntegrityProbeManager(
    private val context: Context,
    // The visible activity, for the one measurement that needs a window:
    // whether it is being recorded (screen_capture, Android 15 and later).
    private val activity: () -> Activity? = { null },
) {
    companion object {
        // 1 = name-based hook detection only (runtime_maps token scan).
        // 2 = adds the structural probes: instrumentation_threads,
        //     exec_mappings, and the native code_integrity buckets. Every
        //     report carries this, so a stored report says which probe set
        //     produced it - see DESIGN.md 29.
        // 4 = volunteers device and network on every scan, and answers the
        //     optional measurements the server asks for (DESIGN.md 80).
        // 5 = adds the optional measurements of what can read or drive the
        //     phone, screen capture, location and mock locations (DESIGN.md 82).
        private const val COLLECTOR_VERSION = 5
        // Sent with every scan whether or not the server asked: the server
        // tolerates probes beyond its plan but refuses a report missing one it
        // asked for, so a probe new to this collector stays out of the plan and
        // every older client keeps working (DESIGN.md 80).
        private val volunteeredProbes = listOf("device", "network")
        // The optional measurements this collector knows. Each is collected
        // only when the server asks for it AND the app enabled it.
        private val optionalMeasurements = setOf(
            "local_addresses", "accessibility", "notification_access", "other_access",
            "screen_capture", "location", "mock_location"
        )
        // Apps listed per capability, at most (DESIGN.md 82).
        private const val MAX_APPS = 32
        // Remote-control apps scammers have their victims install. Android 11
        // and later show an app only the packages it names in advance, so the
        // same names are in the manifest's <queries> (DESIGN.md 82).
        private val remoteAccessPackages = listOf(
            "com.anydesk.anydeskandroid",
            "com.teamviewer.quicksupport.market",
            "com.carriez.flutter_hbb",
            "com.sand.airdroid"
        )
        private const val MAX_TEXT = 8192
        // Every shell command is bounded (review, DESIGN.md 63): one hung
        // child used to block its probe, and the whole scan, indefinitely.
        private const val COMMAND_TIMEOUT_MS = 3000L
        private val suspiciousRuntimeTokens = listOf(
            "frida", "gadget", "objection", "xposed", "lsposed",
            "substrate", "cydia", "zygisk", "riru", "magisk",
            "kernelsu", "apatch"
        )
        private val rootPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/sbin/magisk",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/ksu",
            "/data/adb/ap",
            "/metadata/adb/magisk"
        )
    }

    @Volatile private var cachedApkSha256: String? = null

    // Native code-integrity component. Loaded best-effort: if it is absent the
    // probe degrades to reporting checked=false rather than crashing.
    private external fun nativeCodeIntegrity(): String?

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("codeintegrity")
        true
    } catch (_: Throwable) {
        false
    }

    fun collect(
        requiredProbes: List<String>,
        challengeNonce: String,
        testFixture: String? = null,
        optionalProbes: List<String> = emptyList(),
        enabledMeasurements: Set<String> = emptySet(),
    ): Map<String, Any> {
        val probes = linkedMapOf<String, Any>()
        for (probe in requiredProbes.distinct()) {
            probes[probe] = runProbe(probe, enabledMeasurements)
        }
        for (probe in volunteeredProbes) {
            if (!probes.containsKey(probe)) probes[probe] = runProbe(probe, enabledMeasurements)
        }
        for (probe in optionalProbes.distinct()) {
            if (!probes.containsKey(probe) && probe in optionalMeasurements) {
                probes[probe] = runProbe(probe, enabledMeasurements)
            }
        }

        applyDebugTestFixture(probes, testFixture)

        return linkedMapOf(
            "collector_version" to COLLECTOR_VERSION,
            "platform" to "android",
            "challenge_nonce_echo" to challengeNonce,
            "sdk_int" to Build.VERSION.SDK_INT,
            "test_fixture_applied" to (testFixture ?: ""),
            "probes" to probes
        )
    }

    private fun runProbe(probe: String, enabledMeasurements: Set<String>): Map<String, Any> =
        try {
            when (probe) {
                "app_identity" -> probeAppIdentity()
                "debug_state" -> probeDebugState()
                "root_files" -> probeRootFiles()
                "root_shell" -> probeRootShell()
                "system_properties" -> probeSystemProperties()
                "selinux" -> probeSelinux()
                "mounts" -> probeMounts()
                "runtime_maps" -> probeRuntimeMaps()
                "tracer" -> probeTracer()
                "frida_ports" -> probeFridaPorts()
                "emulator" -> probeEmulator()
                "developer_settings" -> probeDeveloperSettings()
                "instrumentation_threads" -> probeInstrumentationThreads()
                "exec_mappings" -> probeExecMappings()
                "code_integrity" -> probeCodeIntegrity()
                "device" -> probeDevice()
                "network" -> probeNetwork()
                "local_addresses" ->
                    if (probe in enabledMeasurements) probeLocalAddresses() else notEnabled()
                "accessibility" ->
                    if (probe in enabledMeasurements) probeAccessibility() else notEnabled()
                "notification_access" ->
                    if (probe in enabledMeasurements) probeNotificationAccess() else notEnabled()
                "other_access" ->
                    if (probe in enabledMeasurements) probeOtherAccess() else notEnabled()
                "screen_capture" ->
                    if (probe in enabledMeasurements) probeScreenCapture() else notEnabled()
                "location" ->
                    if (probe in enabledMeasurements) probeLocation() else notEnabled()
                "mock_location" ->
                    if (probe in enabledMeasurements) probeMockLocation() else notEnabled()
                else -> resultUnsupported("Unknown probe requested by server")
            }
        } catch (error: Throwable) {
            linkedMapOf(
                "status" to "error",
                "error_type" to error.javaClass.simpleName,
                "error" to ((error.message ?: "probe failed").take(240))
            )
        }

    /**
     * DEBUG-BUILD-ONLY integrity fixtures used to prove server scoring and
     * enforcement without rooting or instrumenting the known-good test phone.
     *
     * This is intentionally unavailable when the installed APK is not
     * debuggable. A release build therefore cannot request these
     * synthetic measurements through the Flutter method channel.
     */
    private fun applyDebugTestFixture(
        probes: MutableMap<String, Any>,
        testFixture: String?,
    ) {
        val fixture = testFixture?.trim().orEmpty()
        if (fixture.isEmpty()) return

        val appIsDebuggable =
            (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!appIsDebuggable) {
            throw IllegalStateException(
                "Integrity test fixtures are disabled in non-debuggable builds."
            )
        }

        when (fixture) {
            "frida_runtime" -> {
                probes["runtime_maps"] = ok(
                    "suspicious_tokens" to listOf("frida", "gadget"),
                    "suspicious_line_count" to 2,
                    "test_fixture" to fixture,
                )
            }

            "frida_port" -> {
                probes["frida_ports"] = ok(
                    "open_ports" to listOf(27042),
                    "test_fixture" to fixture,
                )
            }

            "hook_framework" -> {
                probes["runtime_maps"] = ok(
                    "suspicious_tokens" to listOf("lsposed", "zygisk"),
                    "suspicious_line_count" to 2,
                    "test_fixture" to fixture,
                )
            }

            "root_su" -> {
                probes["root_files"] = ok(
                    "found_paths" to listOf("/data/adb/magisk"),
                    "build_tags" to (Build.TAGS ?: ""),
                    "test_keys" to false,
                    "test_fixture" to fixture,
                )
                probes["root_shell"] = ok(
                    "su_path" to "/system/xbin/su",
                    "su_found" to true,
                    "test_fixture" to fixture,
                )
            }

            "writable_mount" -> {
                probes["mounts"] = ok(
                    "protected_rw_mounts" to listOf(
                        "/system:rw,seclabel,relatime"
                    ),
                    "test_fixture" to fixture,
                )
            }

            else -> throw IllegalArgumentException(
                "Unknown integrity test fixture: $fixture"
            )
        }
    }

    private fun ok(vararg pairs: Pair<String, Any?>): Map<String, Any> {
        val result = linkedMapOf<String, Any>("status" to "ok")
        for ((key, value) in pairs) {
            if (value != null) result[key] = value
        }
        return result
    }

    // A probe that could not make its measurement says so, rather than
    // reporting "ok" with nothing in it: unknown is not clean (review R4,
    // DESIGN.md 76; evidence contract 3).
    private fun unavailable(reason: String): Map<String, Any> = linkedMapOf(
        "status" to "error",
        "error" to reason
    )

    private fun resultUnsupported(reason: String): Map<String, Any> = linkedMapOf(
        "status" to "unsupported",
        "reason" to reason
    )

    // An optional measurement the server asked for but this app's developers
    // did not enable: the business asked, the app declined (DESIGN.md 80).
    private fun notEnabled(): Map<String, Any> = linkedMapOf("status" to "not_enabled")

    /** The OS and the hardware model, and how current the security patches are. */
    private fun probeDevice(): Map<String, Any> = ok(
        "release" to (Build.VERSION.RELEASE ?: ""),
        "sdk_int" to Build.VERSION.SDK_INT,
        "security_patch" to
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else ""),
        "manufacturer" to (Build.MANUFACTURER ?: ""),
        "brand" to (Build.BRAND ?: ""),
        "model" to (Build.MODEL ?: ""),
        "device" to (Build.DEVICE ?: ""),
        "build_id" to (Build.ID ?: ""),
        "fingerprint" to (Build.FINGERPRINT ?: "").take(256)
    )

    /**
     * Whether a VPN is up and an HTTP proxy is set, as the system's own
     * connectivity service says (ACCESS_NETWORK_STATE, granted at install). A
     * VPN is a network of its own, so every network is asked, not only the
     * default one. Interface names only - never an address.
     */
    private fun probeNetwork(): Map<String, Any> {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return unavailable("ConnectivityManager is not available")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return unavailable("needs Android 6 or newer")
        }
        val transports = linkedSetOf<String>()
        manager.activeNetwork?.let { network ->
            manager.getNetworkCapabilities(network)?.let { caps ->
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transports.add("wifi")
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transports.add("cellular")
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transports.add("ethernet")
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transports.add("vpn")
            }
        }
        @Suppress("DEPRECATION")
        val vpn = manager.allNetworks.any { network ->
            manager.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
        val proxy = manager.defaultProxy != null ||
            !System.getProperty("http.proxyHost").isNullOrBlank()
        val interfaces = mutableListOf<String>()
        try {
            NetworkInterface.getNetworkInterfaces()?.let { all ->
                for (item in Collections.list(all)) {
                    if (item.isUp && !item.isLoopback) interfaces.add(item.name.take(32))
                }
            }
        } catch (_: Throwable) {
            // Names are context; the two answers above stand without them.
        }
        return ok(
            "vpn_active" to vpn,
            "http_proxy_configured" to proxy,
            "transports" to transports.toList(),
            "interfaces" to interfaces.distinct().take(32)
        )
    }

    /**
     * The phone's own IP addresses, per interface - an optional measurement
     * (DESIGN.md 80). Link-local addresses are left out: they can carry the
     * hardware address, which the platforms deliberately hide.
     */
    private fun probeLocalAddresses(): Map<String, Any> {
        val addresses = mutableListOf<Map<String, Any>>()
        val all = NetworkInterface.getNetworkInterfaces()
            ?: return unavailable("no network interface could be listed")
        for (item in Collections.list(all)) {
            if (!item.isUp || item.isLoopback) continue
            for (address in Collections.list(item.inetAddresses)) {
                if (address.isLoopbackAddress || address.isLinkLocalAddress) continue
                if (addresses.size >= 32) break
                addresses.add(
                    linkedMapOf(
                        "interface" to item.name.take(32),
                        "address" to (address.hostAddress ?: "").substringBefore('%').take(64)
                    )
                )
            }
        }
        return ok("addresses" to addresses)
    }

    /**
     * One app holding a capability (DESIGN.md 82): its package and component
     * class, whether it is part of the system, and which package installed it
     * ("" for none - adb, or an installer that names nobody). system and
     * installer are left out where Android hides the app from this one; the
     * server then calls its source unknown, which is never evidence. The
     * server, not the phone, decides what counts as an app store.
     */
    private fun appEntry(
        packageName: String,
        component: String? = null,
        knownInfo: ApplicationInfo? = null,
    ): Map<String, Any> {
        val entry = linkedMapOf<String, Any>("package" to packageName.take(128))
        if (component != null) entry["service"] = component.take(200)
        val pm = context.packageManager
        val info = knownInfo ?: try {
            pm.getApplicationInfo(packageName, 0)
        } catch (_: Throwable) {
            null
        }
        val installer: String? = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName ?: ""
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName) ?: ""
            }
        } catch (_: Throwable) {
            null
        }
        if (info != null) {
            entry["system"] = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (installer != null) entry["installer"] = installer.take(128)
        }
        return entry
    }

    /**
     * Every Accessibility service that is on, and the keyboard in use - the
     * two ways banking trojans read what is typed (DESIGN.md 82). The
     * Accessibility manager's list is compared with the system setting it is
     * built from: a service the setting names that the manager does not report
     * is hiding, as an Android bug allowed until the December 2022 patch.
     */
    private fun probeAccessibility(): Map<String, Any> {
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return unavailable("AccessibilityManager is not available")
        val services = mutableListOf<Map<String, Any>>()
        val reported = mutableSetOf<String>()
        for (info in manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)) {
            val service = info.resolveInfo?.serviceInfo ?: continue
            if (!reported.add(ComponentName(service.packageName, service.name).flattenToString())) continue
            if (services.size < MAX_APPS) {
                services.add(appEntry(service.packageName, service.name, service.applicationInfo))
            }
        }
        val hidden = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            ?.split(':')
            ?.mapNotNull { ComponentName.unflattenFromString(it.trim())?.flattenToString() }
            ?.filter { it !in reported }
            ?.distinct()
            ?: emptyList()
        val result = linkedMapOf<String, Any>(
            "status" to "ok",
            "services" to services,
            "settings_only" to hidden.take(MAX_APPS).map { it.take(200) },
            // More than this collector sends: the server says so, never guesses.
            "truncated" to (reported.size > MAX_APPS || hidden.size > MAX_APPS)
        )
        Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
            ?.let { ComponentName.unflattenFromString(it.trim()) }
            ?.let { result["keyboard"] = appEntry(it.packageName, it.className) }
        return result
    }

    /** Every app allowed to read the phone's notifications - one-time codes among them. */
    private fun probeNotificationAccess(): Map<String, Any> {
        // Not a public constant; AndroidX's NotificationManagerCompat reads the
        // same setting. Unreadable, it throws, and the probe answers error.
        val all = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
            ?.split(':')
            ?.mapNotNull { ComponentName.unflattenFromString(it.trim()) }
            ?.distinctBy { it.flattenToString() }
            ?: emptyList()
        return ok(
            "listeners" to all.take(MAX_APPS).map { appEntry(it.packageName, it.className) },
            "truncated" to (all.size > MAX_APPS)
        )
    }

    /** The active device administrators, and the known remote-control apps installed. */
    private fun probeOtherAccess(): Map<String, Any> {
        val policy = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return unavailable("DevicePolicyManager is not available")
        val active = policy.activeAdmins ?: emptyList()
        val admins = active.take(MAX_APPS).map { appEntry(it.packageName, it.className) }
        val pm = context.packageManager
        val remote = remoteAccessPackages.filter { name ->
            try {
                pm.getPackageInfo(name, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }.map { appEntry(it) }
        return ok(
            "device_admins" to admins,
            "remote_access_apps" to remote,
            "truncated" to (active.size > MAX_APPS)
        )
    }

    /**
     * Whether this app's window is being recorded (Android 15 and later, with
     * DETECT_SCREEN_RECORDING, a normal permission the app declares), and how
     * many displays besides the phone's own are on and public: casting,
     * mirroring, an external screen - which this cannot tell apart. A display
     * that is off (a foldable's other screen) or private to another app is
     * not counted. Below Android 15 recording is left out - unknown, not "no".
     */
    private fun probeScreenCapture(): Map<String, Any> {
        val result = linkedMapOf<String, Any>("status" to "ok")
        val window = activity()?.windowManager
        if (Build.VERSION.SDK_INT >= 35 && window != null &&
            context.checkSelfPermission("android.permission.DETECT_SCREEN_RECORDING") ==
            PackageManager.PERMISSION_GRANTED
        ) {
            val callback = Consumer<Int> { }
            try {
                val state = window.addScreenRecordingCallback(Executor { it.run() }, callback)
                result["recording"] = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
            } finally {
                window.removeScreenRecordingCallback(callback)
            }
        }
        val displays = (context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager)?.displays
            ?: return unavailable("DisplayManager is not available")
        result["external_displays"] = displays.count {
            it.displayId != Display.DEFAULT_DISPLAY && it.state == Display.STATE_ON &&
                (it.flags and Display.FLAG_PRIVATE) == 0
        }
        return result
    }

    private fun locationPermission(): String = when {
        context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED -> "precise"
        context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED -> "approximate"
        else -> "none"
    }

    /**
     * The newest location the phone already holds, from any enabled provider:
     * never a fresh fix (no GPS power, no waiting) and never a prompt - only
     * the app asks for the permission, on its own screen.
     */
    @SuppressLint("MissingPermission")
    private fun lastKnownLocation(): Location? {
        val manager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return null
        return manager.getProviders(true).mapNotNull { provider ->
            try {
                manager.getLastKnownLocation(provider)
            } catch (_: SecurityException) {
                null
            }
        }.maxByOrNull { it.elapsedRealtimeNanos }
    }

    private fun fixAgeSeconds(fix: Location): Long =
        maxOf(0L, (SystemClock.elapsedRealtimeNanos() - fix.elapsedRealtimeNanos) / 1_000_000_000L)

    /** The last known location (DESIGN.md 82): the most identifying measurement here. */
    private fun probeLocation(): Map<String, Any> {
        val permission = locationPermission()
        val result = linkedMapOf<String, Any>("status" to "ok", "permission" to permission)
        if (permission == "none") return result
        val fix = lastKnownLocation() ?: return result
        result["latitude"] = fix.latitude
        result["longitude"] = fix.longitude
        if (fix.hasAccuracy()) result["accuracy_m"] = fix.accuracy.toDouble()
        result["age_seconds"] = fixAgeSeconds(fix)
        result["provider"] = (fix.provider ?: "").take(32)
        return result
    }

    /** Whether that last location came from a mock-location app; no coordinates. */
    private fun probeMockLocation(): Map<String, Any> {
        val permission = locationPermission()
        val result = linkedMapOf<String, Any>("status" to "ok", "permission" to permission)
        if (permission == "none") return result
        val fix = lastKnownLocation() ?: return result
        result["mock"] = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            fix.isMock
        } else {
            @Suppress("DEPRECATION")
            fix.isFromMockProvider
        }
        result["age_seconds"] = fixAgeSeconds(fix)
        return result
    }

    @Suppress("DEPRECATION")
    private fun probeAppIdentity(): Map<String, Any> {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val packageInfo = pm.getPackageInfo(context.packageName, flags)
        val appInfo = packageInfo.applicationInfo ?: context.applicationInfo
        val certDigests = mutableListOf<String>()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signatures = packageInfo.signingInfo?.let { signingInfo ->
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            }.orEmpty()

            signatures.forEach { signature ->
                certDigests.add(sha256Hex(signature.toByteArray()))
            }
        } else {
            packageInfo.signatures?.forEach { signature ->
                certDigests.add(sha256Hex(signature.toByteArray()))
            }
        }
        certDigests.sort()

        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(context.packageName)
            }
        } catch (_: Throwable) {
            null
        }

        val apkHash = cachedApkSha256 ?: sha256File(File(appInfo.sourceDir)).also {
            cachedApkSha256 = it
        }
        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            packageInfo.versionCode.toLong()
        }

        return ok(
            "package_name" to context.packageName,
            "version_name" to (packageInfo.versionName ?: ""),
            "version_code" to versionCode,
            "debuggable" to ((appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0),
            "allow_backup" to ((appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0),
            "cert_sha256" to certDigests,
            "apk_sha256" to apkHash,
            "installer_package" to installer,
            "source_dir" to appInfo.sourceDir
        )
    }

    private fun probeDebugState(): Map<String, Any> = ok(
        "debugger_connected" to Debug.isDebuggerConnected(),
        "waiting_for_debugger" to Debug.waitingForDebugger()
    )

    private fun probeRootFiles(): Map<String, Any> {
        val found = rootPaths.filter { path ->
            try { File(path).exists() } catch (_: Throwable) { false }
        }
        return ok(
            "found_paths" to found,
            "build_tags" to (Build.TAGS ?: ""),
            "test_keys" to ((Build.TAGS ?: "").lowercase(Locale.US).contains("test-keys"))
        )
    }

    private fun probeRootShell(): Map<String, Any> {
        // A lookup that never finishes is not "no su": fail the probe, which the
        // server scores as integrity_probe_failed rather than as clean.
        val whichSu = runCommand(listOf("/system/bin/sh", "-c", "command -v su || which su || true"))
            ?: throw IllegalStateException("su lookup timed out")
        return ok(
            "su_path" to whichSu.trim().take(512),
            "su_found" to whichSu.trim().isNotEmpty()
        )
    }

    private fun probeSystemProperties(): Map<String, Any> {
        val names = listOf(
            "ro.secure",
            "ro.debuggable",
            "ro.build.type",
            "ro.build.tags",
            "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state",
            "ro.boot.veritymode"
        )
        val values = linkedMapOf<String, String>()
        for (name in names) {
            values[name] = (runCommand(listOf("/system/bin/getprop", name))
                ?: throw IllegalStateException("getprop $name timed out")).trim().take(256)
        }
        return ok("properties" to values)
    }

    private fun probeSelinux(): Map<String, Any> {
        // Collect SELinux state using two independent local views. Some OEMs do
        // not expose /system/bin/getenforce consistently to an application
        // process even though SELinux itself is enforcing. /sys/fs/selinux/enforce
        // is the authoritative kernel boolean when readable: 1=enforcing,
        // 0=permissive. Never turn command errors into a security verdict here;
        // the server normalizes and scores the evidence.
        // A timed-out getenforce is unknown, like an unreadable one: unknown
        // SELinux state is telemetry, never evidence (server scores it +0).
        val mode = (runCommand(
            listOf("/system/bin/sh", "-c", "getenforce 2>/dev/null || true")
        ) ?: "").trim().lineSequence().firstOrNull().orEmpty().take(64)

        val enforceValue = try {
            val file = File("/sys/fs/selinux/enforce")
            if (file.canRead()) file.readText().trim().take(8) else ""
        } catch (_: Throwable) {
            ""
        }

        val normalizedMode = when {
            mode.equals("Enforcing", ignoreCase = true) -> "enforcing"
            mode.equals("Permissive", ignoreCase = true) -> "permissive"
            mode.equals("Disabled", ignoreCase = true) -> "disabled"
            enforceValue == "1" -> "enforcing"
            enforceValue == "0" -> "permissive"
            else -> "unknown"
        }

        return ok(
            "mode" to normalizedMode,
            "getenforce" to mode,
            "enforce_value" to enforceValue
        )
    }

    private fun probeMounts(): Map<String, Any> {
        val protectedPrefixes = listOf("/system", "/vendor", "/product", "/odm", "/system_ext")
        val writable = mutableListOf<String>()
        val mountFile = File("/proc/mounts")
        if (mountFile.canRead()) {
            mountFile.forEachLine { line ->
                val parts = line.split(' ')
                if (parts.size >= 4) {
                    val mountPoint = parts[1]
                    val options = parts[3].split(',')
                    if (protectedPrefixes.any { mountPoint == it || mountPoint.startsWith("$it/") } &&
                        options.contains("rw")) {
                        writable.add("$mountPoint:${parts[3]}")
                    }
                }
            }
        }
        return ok("protected_rw_mounts" to writable.distinct().take(32))
    }

    private fun probeRuntimeMaps(): Map<String, Any> {
        val found = linkedSetOf<String>()
        var suspiciousLines = 0
        var mapsLines = 0
        val file = File("/proc/self/maps")
        if (!file.canRead()) return unavailable("/proc/self/maps is not readable")
        run {
            file.forEachLine { original ->
                mapsLines++
                val line = original.lowercase(Locale.US)
                var lineMatched = false
                for (token in suspiciousRuntimeTokens) {
                    if (line.contains(token)) {
                        found.add(token)
                        lineMatched = true
                    }
                }
                if (lineMatched) suspiciousLines++
            }
        }
        if (mapsLines == 0) return unavailable("/proc/self/maps returned no lines")
        return ok(
            "suspicious_tokens" to found.toList(),
            "suspicious_line_count" to suspiciousLines,
            "maps_lines" to mapsLines
        )
    }

    private fun probeTracer(): Map<String, Any> {
        var tracerPid = 0
        var seccomp = -1
        var noNewPrivs = -1
        val file = File("/proc/self/status")
        if (file.canRead()) {
            file.forEachLine { line ->
                when {
                    line.startsWith("TracerPid:") -> tracerPid = line.substringAfter(':').trim().toIntOrNull() ?: 0
                    line.startsWith("Seccomp:") -> seccomp = line.substringAfter(':').trim().toIntOrNull() ?: -1
                    line.startsWith("NoNewPrivs:") -> noNewPrivs = line.substringAfter(':').trim().toIntOrNull() ?: -1
                }
            }
        }
        return ok(
            "tracer_pid" to tracerPid,
            "seccomp" to seccomp,
            "no_new_privs" to noNewPrivs
        )
    }

    private fun probeFridaPorts(): Map<String, Any> {
        val ports = listOf(27042, 27043)
        val open = mutableListOf<Int>()
        for (port in ports) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 80)
                    open.add(port)
                }
            } catch (_: Throwable) {
                // Closed/refused is the expected normal result.
            }
        }
        return ok("open_ports" to open)
    }

    private fun probeEmulator(): Map<String, Any> {
        val reasons = mutableListOf<String>()
        fun contains(value: String?, token: String) =
            value?.lowercase(Locale.US)?.contains(token) == true

        if (Build.FINGERPRINT.startsWith("generic") || contains(Build.FINGERPRINT, "emulator")) reasons.add("fingerprint")
        if (contains(Build.MODEL, "google_sdk") || contains(Build.MODEL, "emulator") || contains(Build.MODEL, "android sdk built for")) reasons.add("model")
        if (contains(Build.MANUFACTURER, "genymotion")) reasons.add("manufacturer")
        if (contains(Build.PRODUCT, "sdk") || contains(Build.PRODUCT, "emulator") || contains(Build.PRODUCT, "simulator")) reasons.add("product")
        if (contains(Build.HARDWARE, "goldfish") || contains(Build.HARDWARE, "ranchu")) reasons.add("hardware")
        if (contains(Build.BOARD, "goldfish")) reasons.add("board")

        return ok(
            "suspected" to reasons.isNotEmpty(),
            "reasons" to reasons,
            "model" to Build.MODEL,
            "manufacturer" to Build.MANUFACTURER,
            "product" to Build.PRODUCT,
            "hardware" to Build.HARDWARE
        )
    }

    private fun probeDeveloperSettings(): Map<String, Any> {
        val resolver = context.contentResolver
        val adb = try { Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) != 0 } catch (_: Throwable) { false }
        val developer = try { Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0 } catch (_: Throwable) { false }
        return ok(
            "adb_enabled" to adb,
            "developer_options_enabled" to developer
        )
    }

    /**
     * Instrumentation-runtime thread names.
     *
     * Structural, not name-of-file based: Frida's Gum runtime and its GLib
     * dependency spawn threads with names compiled into the framework
     * (gum-js-loop, pool-frida, gmain, gdbus). Renaming the injected .so - which
     * defeats the /proc/self/maps pathname scan - does not rename these threads,
     * so an idle, renamed Frida Gadget is still visible here. Reads
     * /proc/self/task/<tid>/comm, which an app can always read for its own
     * threads regardless of SELinux.
     */
    private fun probeInstrumentationThreads(): Map<String, Any> {
        // Unmistakably Frida/Gum: these are compiled into the framework, so a
        // renamed injected .so keeps them. gum-js-loop is the Gum JS event loop.
        val fridaThreads = listOf("gum-js-loop", "gum-js", "pool-frida")
        // GLib runtime threads: Frida pulls GLib in, and Android apps almost
        // never link GLib themselves, but reported separately so the server can
        // weight them as corroborating rather than conclusive.
        val glibThreads = listOf("gmain", "gdbus", "pool-spawner")
        val fridaHits = linkedSetOf<String>()
        val glibHits = linkedSetOf<String>()
        val tokenHits = linkedSetOf<String>()
        var count = 0
        val tasks = File("/proc/self/task").listFiles()
        if (tasks != null) {
            for (task in tasks) {
                val comm = File(task, "comm")
                if (!comm.canRead()) continue
                val name = try { comm.readText().trim() } catch (_: Throwable) { continue }
                if (name.isEmpty()) continue
                count++
                val lower = name.lowercase(Locale.US)
                for (t in fridaThreads) if (lower == t || lower.startsWith(t)) fridaHits.add(t)
                for (t in glibThreads) if (lower == t) glibHits.add(t)
                for (t in suspiciousRuntimeTokens) if (lower.contains(t)) tokenHits.add(t)
            }
        }
        // A running process always has threads; none enumerated means the
        // probe saw nothing, not that nothing is there.
        if (count == 0) return unavailable("no thread of this process could be enumerated")
        return ok(
            "frida_threads" to fridaHits.toList(),
            "glib_threads" to glibHits.toList(),
            "token_threads" to tokenHits.toList(),
            "thread_count" to count
        )
    }

    /**
     * Structurally suspicious executable memory.
     *
     * Behaviour-based: inline-hooking and injection frameworks allocate
     * executable trampoline/agent memory. Two shapes are rare in a clean,
     * W^X-compliant app and are reported here: mappings that are simultaneously
     * writable and executable, and executable mappings backed by a file marked
     * "(deleted)". Anonymous executable regions carrying a recognized
     * "[anon:...]" label (for example the ART JIT code cache) are counted
     * separately as telemetry and are NOT treated as suspicious, to avoid
     * flagging the legitimate runtime.
     */
    private fun probeExecMappings(): Map<String, Any> {
        var wx = 0
        var deletedExec = 0
        var deletedExecJit = 0
        var deletedExecOwnCode = 0
        // The app's own compiled code: Android recompiles an app in the
        // background after an install or update and replaces these files
        // under the running process (the Huawei did, about a minute after an
        // install, 2026-10-13). Writing here takes installd, system or root --
        // an attacker who can plant code here already owns the device -- so
        // they are counted apart and the server treats them as advisory.
        // Nothing outside oat/ is exempt, not even base.apk.
        val ownCodeDir = File(context.applicationInfo.sourceDir).parentFile?.path?.let { "$it/oat/" }
        var anonExecLabeled = 0
        var anonExecUnlabeled = 0
        val samples = mutableListOf<String>()
        var mapsLines = 0
        val file = File("/proc/self/maps")
        if (!file.canRead()) return unavailable("/proc/self/maps is not readable")
        run {
            file.forEachLine { line ->
                mapsLines++
                val parts = line.trim().split(Regex("\\s+"), limit = 6)
                if (parts.size < 5) return@forEachLine
                val perms = parts[1]
                if (perms.length < 4) return@forEachLine
                val writable = perms[1] == 'w'
                val executable = perms[2] == 'x'
                if (!executable) return@forEachLine
                val path = if (parts.size >= 6) parts[5] else ""
                if (writable) {
                    wx++
                    if (samples.size < 8) samples.add(line.trim().take(160))
                }
                if (path.contains("(deleted)")) {
                    // The ART JIT code cache is a memfd/ashmem region that
                    // always shows as executable and "(deleted)" on a clean
                    // device. Exclude it, or every device is a false positive.
                    val lower = path.lowercase(Locale.US)
                    val isJit = lower.contains("jit-cache") ||
                        lower.contains("dalvik-jit-code-cache") ||
                        lower.contains("dalvik-") ||
                        lower.contains("/art") ||
                        lower.contains("jit-zygote")
                    val mapped = path.removeSuffix("(deleted)").trim()
                    val isOwnCode = ownCodeDir != null && mapped.startsWith(ownCodeDir) &&
                        (mapped.endsWith(".odex") || mapped.endsWith(".vdex") ||
                            mapped.endsWith(".art") || mapped.endsWith(".oat"))
                    if (isJit) {
                        deletedExecJit++
                    } else if (isOwnCode) {
                        deletedExecOwnCode++
                        if (samples.size < 8) samples.add(line.trim().take(160))
                    } else {
                        deletedExec++
                        if (samples.size < 8) samples.add(line.trim().take(160))
                    }
                }
                if (path.isEmpty()) {
                    anonExecUnlabeled++
                } else if (path.startsWith("[anon:")) {
                    anonExecLabeled++
                }
            }
        }
        if (mapsLines == 0) return unavailable("/proc/self/maps returned no lines")
        return ok(
            "wx_mappings" to wx,
            "maps_lines" to mapsLines,
            "deleted_exec_mappings" to deletedExec,
            "deleted_exec_jit" to deletedExecJit,
            "deleted_exec_own_code" to deletedExecOwnCode,
            "anon_exec_labeled" to anonExecLabeled,
            "anon_exec_unlabeled" to anonExecUnlabeled,
            "samples" to samples
        )
    }

    /**
     * Code integrity of libc: in-memory .text versus the same bytes on disk.
     *
     * The purest structural check. An inline hook overwrites the prologue of a
     * hooked function with a trampoline, so the executable segment loaded in
     * memory diverges from the file on disk. This is name-independent and
     * behaviour-based - it catches any inline-hooking library, whatever it is
     * called. The executable segment is not modified at runtime by the dynamic
     * linker (relocations land in the GOT/data segments, not in .text), so on a
     * clean device the two are byte-identical. Reads a bounded window through
     * /proc/self/mem, which an app may read for its own address space.
     */
    private fun probeCodeIntegrity(): Map<String, Any> {
        // Native reads our own mapped r-x pages by pointer, so unlike the
        // /proc/self/mem path it is not blocked by SELinux. It compares three
        // buckets of libraries in memory against disk: core (libc/libart),
        // ext (other system hook targets incl. TLS), and app (the app's own
        // native code). Any inline hook overwrites a prologue and shows up as
        // a byte difference, whatever the hooking framework is called.
        if (!nativeAvailable) {
            return ok("checked" to false, "reason" to "native_unavailable")
        }
        val started = System.nanoTime()
        val json = try {
            nativeCodeIntegrity()
        } catch (error: Throwable) {
            return ok("checked" to false, "reason" to ("native_error:" + error.javaClass.simpleName))
        }
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        if (json.isNullOrEmpty()) {
            return ok("checked" to false, "reason" to "native_no_result")
        }
        return try {
            val o = JSONObject(json)
            val result = linkedMapOf<String, Any>(
                "status" to "ok",
                "checked" to o.optBoolean("checked", false),
                "diff_bytes" to o.optLong("diff_bytes", 0),
                "core_compared_bytes" to o.optLong("core_compared_bytes", 0),
                "core_diff_bytes" to o.optLong("core_diff_bytes", 0),
                "ext_compared_bytes" to o.optLong("ext_compared_bytes", 0),
                "ext_diff_bytes" to o.optLong("ext_diff_bytes", 0),
                "ext_libs_diff" to o.optInt("ext_libs_diff", 0),
                "app_compared_bytes" to o.optLong("app_compared_bytes", 0),
                "app_diff_bytes" to o.optLong("app_diff_bytes", 0),
                "app_libs_diff" to o.optInt("app_libs_diff", 0),
                // Visibility into execute-only mappings: a bucket that skipped
                // everything reads as clean unless these are reported.
                "xom_regions_unlocked" to o.optInt("xom_regions_unlocked", 0),
                "xom_regions_unreadable" to o.optInt("xom_regions_unreadable", 0),
                "diffed_libs" to o.optString("diffed_libs", ""),
                // Wall time of the native comparison, for the scan-cost figures
                // the review asked for.
                "elapsed_ms" to elapsedMs
            )
            // Coverage per bucket (DESIGN.md 63): expected = compared + skipped +
            // unreadable, so partial measurement is visible, never read as
            // clean. Copied only when the native side reported them.
            for (bucket in listOf("core", "ext", "app")) {
                for (field in listOf("expected_bytes", "skipped_bytes", "unreadable_bytes")) {
                    val key = "${bucket}_$field"
                    if (o.has(key)) result[key] = o.optLong(key, 0)
                }
                val complete = "${bucket}_complete"
                if (o.has(complete)) result[complete] = o.optBoolean(complete, false)
            }
            if (o.has("protect_restore_failures")) {
                result["protect_restore_failures"] = o.optInt("protect_restore_failures", 0)
            }
            result
        } catch (error: Throwable) {
            ok("checked" to false, "reason" to ("parse_error:" + error.javaClass.simpleName))
        }
    }

    /**
     * Runs one command with a deadline. Returns its output (at most MAX_TEXT),
     * "" if it could not be run, or null if it did not finish within
     * COMMAND_TIMEOUT_MS -- the child is then killed, and the caller decides
     * what an unfinished measurement means for its probe. The output is read on
     * a separate thread because a blocking read is exactly what used to hang.
     */
    private fun runCommand(command: List<String>): String? {
        val process = try {
            ProcessBuilder(command).redirectErrorStream(true).start()
        } catch (_: Throwable) {
            return ""
        }
        val output = StringBuilder()
        val reader = Thread {
            try {
                BufferedReader(InputStreamReader(process.inputStream)).use { input ->
                    var line: String?
                    while (input.readLine().also { line = it } != null) {
                        synchronized(output) {
                            if (output.length < MAX_TEXT) output.append(line).append('\n')
                        }
                    }
                }
            } catch (_: Throwable) {
            }
        }
        reader.isDaemon = true
        reader.start()
        return try {
            if (!process.waitFor(COMMAND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                null
            } else {
                reader.join(500)
                synchronized(output) { output.toString().take(MAX_TEXT) }
            }
        } catch (_: InterruptedException) {
            process.destroyForcibly()
            Thread.currentThread().interrupt()
            null
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun sha256File(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }
}
