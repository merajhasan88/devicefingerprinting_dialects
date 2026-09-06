import Foundation
import CryptoKit
import MachO
import Security

/// Local integrity measurement collector for iOS.
///
/// IMPORTANT: these are risk signals, not remote attestation. On a jailbroken
/// device an attacker may be able to lie about local state. The server scores
/// these raw measurements together with server-observed behaviour and never
/// trusts a client-provided score - the collector deliberately computes no
/// score of its own, exactly like the Android host.
///
/// The probe names and every field name below are a hard contract with
/// `_score_ios_integrity` in device_trust_server.py. Renaming a field silently
/// disables the rule that reads it.
final class IntegrityProbeManager {
    /// Per-platform numbering. 1 = the baseline probe set below. A future 2
    /// would add the dyld code-integrity analogue of Android's `code_integrity`
    /// (see DESIGN.md 33.4).
    private static let collectorVersion = 1
    private static let maxTextLength = 8192

    /// Loaded-image names that indicate instrumentation or a hooking runtime.
    /// This is the iOS counterpart of the /proc/self/maps token scan - and it
    /// carries the same known weakness: it matches on NAME, so a renamed
    /// library evades it. See DESIGN.md 27.11 for how that was demonstrated on
    /// Android and 33.4 for the structural answer.
    private static let suspiciousImageTokens = [
        "frida", "gadget", "objection", "cynject", "cycript",
        "substrate", "mobilesubstrate", "substitute", "libhooker",
        "ellekit", "cydia", "shadow", "flex", "libsparkapplist",
    ]

    /// Classic jailbreak filesystem artifacts, including rootless (/var/jb)
    /// layouts used by modern jailbreaks such as palera1n and Dopamine.
    private static let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/usr/libexec/ssh-keysign",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/usr/libexec/ellekit",
        "/var/jb",
        "/var/jb/usr/lib/TweakInject",
        "/.bootstrapped_electra",
        "/taurine",
        "/.installed_unc0ver",
    ]

    // MARK: - Entry point

    func collect(
        requiredProbes: [String],
        challengeNonce: String,
        testFixture: String?
    ) -> [String: Any] {
        var probes: [String: Any] = [:]

        for probe in NSOrderedSet(array: requiredProbes).array as? [String] ?? requiredProbes {
            probes[probe] = runProbe(probe)
        }

        // Debug-only synthetic fixtures exist on Android but were retired
        // (DESIGN.md 25.7) and are deliberately not implemented here. The
        // parameter is accepted and echoed so the channel contract matches.
        return [
            "collector_version": IntegrityProbeManager.collectorVersion,
            "platform": "ios",
            "challenge_nonce_echo": challengeNonce,
            "os_version": UIDeviceOSVersion(),
            "test_fixture_applied": testFixture ?? "",
            "probes": probes,
        ]
    }

    private func runProbe(_ name: String) -> [String: Any] {
        switch name {
        case "app_identity":    return probeAppIdentity()
        case "code_signing":    return probeCodeSigning()
        case "debugger":        return probeDebugger()
        case "jailbreak_files": return probeJailbreakFiles()
        case "sandbox":         return probeSandbox()
        case "dyld_images":     return probeDyldImages()
        case "environment":     return probeEnvironment()
        case "simulator":       return probeSimulator()
        default:
            return [
                "status": "unsupported",
                "reason": "Unknown probe requested by server",
            ]
        }
    }

    // MARK: - Probes

    private func probeAppIdentity() -> [String: Any] {
        let bundle = Bundle.main
        var result: [String: Any] = [
            "status": "ok",
            "bundle_id": bundle.bundleIdentifier ?? "",
            "version_name": bundle.infoDictionary?["CFBundleShortVersionString"] as? String ?? "",
            "version_code": bundle.infoDictionary?["CFBundleVersion"] as? String ?? "",
        ]
        // Hash the main executable. The server compares this against a
        // configured baseline when one is set (ios_executable_hash_mismatch).
        if let url = bundle.executableURL,
           let data = try? Data(contentsOf: url, options: .mappedIfSafe) {
            result["executable_sha256"] = SHA256.hash(data: data)
                .map { String(format: "%02x", $0) }.joined()
            result["executable_bytes"] = data.count
        } else {
            result["executable_sha256"] = ""
        }
        return result
    }

    private func probeCodeSigning() -> [String: Any] {
        var result: [String: Any] = ["status": "ok"]

        guard let task = SecTaskCreateFromSelf(kCFAllocatorDefault) else {
            result["status"] = "error"
            result["error"] = "SecTaskCreateFromSelf returned nil"
            return result
        }

        var error: Unmanaged<CFError>?
        let identifier = SecTaskCopySigningIdentifier(task, &error)
        result["signing_identifier"] = (identifier as String?) ?? ""

        func entitlement(_ key: String) -> Any? {
            var entitlementError: Unmanaged<CFError>?
            let value = SecTaskCopyValueForEntitlement(
                task, key as CFString, &entitlementError
            )
            return value as Any?
        }

        // An unsigned build - which is what the jailbroken-device workflow
        // produces - legitimately has neither of these. Empty is reported
        // honestly; the server only compares when a baseline is configured.
        result["team_identifier"] =
            entitlement("com.apple.developer.team-identifier") as? String ?? ""
        result["get_task_allow"] =
            (entitlement("get-task-allow") as? Bool) ?? false

        return result
    }

    /// P_TRACED via sysctl is the standard, non-private debugger check.
    private func probeDebugger() -> [String: Any] {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

        let status = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        if status != 0 {
            return [
                "status": "error",
                "error": "sysctl failed with errno \(errno)",
            ]
        }
        return [
            "status": "ok",
            "traced": (info.kp_proc.p_flag & P_TRACED) != 0,
        ]
    }

    private func probeJailbreakFiles() -> [String: Any] {
        var found: [String] = []
        let manager = FileManager.default
        for path in IntegrityProbeManager.jailbreakPaths {
            // On a clean device the sandbox makes most of these unreadable,
            // which is indistinguishable from absent - and that is fine. A
            // false negative here is safe; the dyld and environment probes
            // catch in-process instrumentation regardless.
            if manager.fileExists(atPath: path) {
                found.append(path)
            }
        }
        return [
            "status": "ok",
            "found_paths": found,
            "checked_count": IntegrityProbeManager.jailbreakPaths.count,
        ]
    }

    /// Attempt a write outside the app container. On a sandboxed device this
    /// must fail; success means the sandbox is not being enforced, which the
    /// server treats as a hard block.
    private func probeSandbox() -> [String: Any] {
        let path = "/private/devicetrust_sandbox_probe.txt"
        var succeeded = false
        do {
            try "probe".write(toFile: path, atomically: true, encoding: .utf8)
            succeeded = true
            // Leave nothing behind on a device where this unexpectedly works.
            try? FileManager.default.removeItem(atPath: path)
        } catch {
            succeeded = false
        }
        return [
            "status": "ok",
            "write_outside_sandbox_succeeded": succeeded,
            "probe_path": path,
        ]
    }

    /// The iOS analogue of scanning /proc/self/maps: walk the images actually
    /// loaded into this process.
    private func probeDyldImages() -> [String: Any] {
        var tokens = Set<String>()
        var suspiciousCount = 0
        let imageCount = _dyld_image_count()

        for index in 0..<imageCount {
            guard let raw = _dyld_get_image_name(index) else { continue }
            let name = String(cString: raw).lowercased()
            var matched = false
            for token in IntegrityProbeManager.suspiciousImageTokens
            where name.contains(token) {
                tokens.insert(token)
                matched = true
            }
            if matched { suspiciousCount += 1 }
        }

        return [
            "status": "ok",
            "suspicious_tokens": Array(tokens).sorted(),
            "suspicious_image_count": suspiciousCount,
            "image_count": Int(imageCount),
        ]
    }

    private func probeEnvironment() -> [String: Any] {
        let inserted = ProcessInfo.processInfo
            .environment["DYLD_INSERT_LIBRARIES"] ?? ""
        return [
            "status": "ok",
            "dyld_insert_libraries": String(inserted.prefix(IntegrityProbeManager.maxTextLength)),
        ]
    }

    private func probeSimulator() -> [String: Any] {
        #if targetEnvironment(simulator)
        let isSimulator = true
        #else
        let isSimulator = ProcessInfo.processInfo
            .environment["SIMULATOR_DEVICE_NAME"] != nil
        #endif
        return [
            "status": "ok",
            "is_simulator": isSimulator,
            "model": deviceModelIdentifier(),
        ]
    }

    // MARK: - Helpers

    private func deviceModelIdentifier() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let mirror = Mirror(reflecting: systemInfo.machine)
        return mirror.children.reduce(into: "") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return }
            identifier += String(UnicodeScalar(UInt8(bitPattern: value)))
        }
    }

    private func UIDeviceOSVersion() -> String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }
}
