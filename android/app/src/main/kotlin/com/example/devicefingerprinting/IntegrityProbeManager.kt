package com.example.devicefingerprinting

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.util.Locale
import org.json.JSONObject

/**
 * Local integrity measurement collector.
 *
 * IMPORTANT: these measurements are risk signals, not remote attestation. On a
 * fully compromised OS an attacker may be able to lie about local state. The
 * server must therefore score these signals together with server-observed
 * device/account behavior and must never trust a client-provided score.
 */
class IntegrityProbeManager(private val context: Context) {
    companion object {
        private const val COLLECTOR_VERSION = 1
        private const val MAX_TEXT = 8192
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
    ): Map<String, Any> {
        val probes = linkedMapOf<String, Any>()
        for (probe in requiredProbes.distinct()) {
            probes[probe] = try {
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
                    else -> resultUnsupported("Unknown probe requested by server")
                }
            } catch (error: Throwable) {
                linkedMapOf(
                    "status" to "error",
                    "error_type" to error.javaClass.simpleName,
                    "error" to ((error.message ?: "probe failed").take(240))
                )
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

    /**
     * DEBUG-BUILD-ONLY integrity fixtures used to prove server scoring and
     * enforcement without rooting or instrumenting the known-good test phone.
     *
     * This is intentionally unavailable when the installed APK is not
     * debuggable. A release Payactiv build therefore cannot request these
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

    private fun resultUnsupported(reason: String): Map<String, Any> = linkedMapOf(
        "status" to "unsupported",
        "reason" to reason
    )

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
        val whichSu = runCommand(listOf("/system/bin/sh", "-c", "command -v su || which su || true"))
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
            values[name] = runCommand(listOf("/system/bin/getprop", name)).trim().take(256)
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
        val mode = runCommand(
            listOf("/system/bin/sh", "-c", "getenforce 2>/dev/null || true")
        ).trim().lineSequence().firstOrNull().orEmpty().take(64)

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
        val file = File("/proc/self/maps")
        if (file.canRead()) {
            file.forEachLine { original ->
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
        return ok(
            "suspicious_tokens" to found.toList(),
            "suspicious_line_count" to suspiciousLines
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
        var anonExecLabeled = 0
        var anonExecUnlabeled = 0
        val samples = mutableListOf<String>()
        val file = File("/proc/self/maps")
        if (file.canRead()) {
            file.forEachLine { line ->
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
                    if (isJit) {
                        deletedExecJit++
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
        return ok(
            "wx_mappings" to wx,
            "deleted_exec_mappings" to deletedExec,
            "deleted_exec_jit" to deletedExecJit,
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
        val json = try {
            nativeCodeIntegrity()
        } catch (error: Throwable) {
            return ok("checked" to false, "reason" to ("native_error:" + error.javaClass.simpleName))
        }
        if (json.isNullOrEmpty()) {
            return ok("checked" to false, "reason" to "native_no_result")
        }
        return try {
            val o = JSONObject(json)
            ok(
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
                "diffed_libs" to o.optString("diffed_libs", "")
            )
        } catch (error: Throwable) {
            ok("checked" to false, "reason" to ("parse_error:" + error.javaClass.simpleName))
        }
    }

    private fun runCommand(command: List<String>): String {
        return try {
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
            val result = BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                val builder = StringBuilder()
                var line: String?
                while (reader.readLine().also { line = it } != null && builder.length < MAX_TEXT) {
                    builder.append(line).append('\n')
                }
                builder.toString()
            }
            process.waitFor()
            result.take(MAX_TEXT)
        } catch (_: Throwable) {
            ""
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
