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
    /// Per-platform numbering. 1 was the baseline probe set; 2 adds
    /// `code_integrity`, the dyld analogue of Android's native probe
    /// (DESIGN.md 33.4), which is what battery item 16 needs.
    private static let collectorVersion = 2
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

        // code_integrity is reported whether or not the server asked for it.
        //
        // The server tolerates probes beyond required_probes but rejects a
        // report that omits a requested one, so a collector cannot be given a
        // new mandatory probe without breaking every client that predates it -
        // here that would mean the .NET iOS collector, which has the same eight
        // probes this one had. Volunteering the measurement instead lets the
        // server score it when present and ignore it when absent, so the two
        // clients can adopt it independently. Promote it to the mandatory list
        // once both report it.
        if probes["code_integrity"] == nil {
            probes["code_integrity"] = runProbe("code_integrity")
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
        case "code_integrity":  return probeCodeIntegrity()
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

    /// Reports this app's own code-signing identity by parsing the Mach-O
    /// signature embedded in its executable on disk.
    ///
    /// The obvious implementation - SecTaskCreateFromSelf plus
    /// SecTaskCopyValueForEntitlement - does not compile for iOS. Those live in
    /// Security/SecTask.h, which Apple ships as public API on macOS only; on
    /// iOS the symbols are private and the build fails with "Cannot find
    /// 'SecTaskCreateFromSelf' in scope".
    ///
    /// Reading our own binary is the better measurement regardless. It reports
    /// what is actually embedded in the file rather than what the kernel was
    /// told at launch, and it degrades honestly: a TrollStore-installed
    /// unsigned build carries no LC_CODE_SIGNATURE at all, which is reported as
    /// signed=false instead of being mistaken for a clean signed app. That is
    /// the same class of trap as an Android integrity bucket reporting
    /// compared_bytes=0 and reading as clean (DESIGN.md 28.8).
    ///
    /// signing_identifier / team_identifier / get_task_allow are a hard
    /// contract with _score_ios_integrity. The remaining fields are additive.
    private func probeCodeSigning() -> [String: Any] {
        var result: [String: Any] = [
            "status": "ok",
            "signing_identifier": "",
            "team_identifier": "",
            "get_task_allow": false,
            "signed": false,
        ]

        guard let url = Bundle.main.executableURL,
              let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            result["status"] = "error"
            result["error"] = "The main executable could not be read."
            return result
        }

        guard let slice = machOSliceOffset(data) else {
            result["status"] = "error"
            result["error"] = "The main executable is not a recognised 64-bit Mach-O image."
            return result
        }

        guard let signature = codeSignatureRange(data, sliceOffset: slice) else {
            // Unsigned - legitimate for the jailbroken-device build. The server
            // only compares these fields when a baseline is configured.
            result["signature_absent"] = true
            return result
        }

        result["signed"] = true
        parseEmbeddedSignature(
            data, offset: signature.offset, size: signature.size, into: &result
        )
        return result
    }

    // MARK: - Code integrity

    /// Compares each loaded image's `__TEXT,__text` in memory against the same
    /// bytes on disk. This is the iOS analogue of Android's native
    /// `code_integrity`, and the field names are a hard contract with
    /// `_score_ios_integrity` mirroring `_score_android_integrity`.
    ///
    /// **Only the app bucket can be measured on iOS, and that is a platform
    /// fact rather than an omission.** Android compares libc and libart
    /// against `/apex/.../libc.so`, real files with real bytes. iOS system
    /// libraries do not exist as individual files: dyld combines them into the
    /// shared cache, so there is nothing to `open()` for UIKit or libobjc.
    /// Those images are therefore counted as *unreadable*, never as clean.
    ///
    /// That distinction is the whole point. An implementation that skipped
    /// them silently would report `ext_compared_bytes: 0, ext_diff_bytes: 0`,
    /// which scores exactly like a pristine device while having measured
    /// nothing — the defect recorded in DESIGN.md 28.8, and again in 34.3, and
    /// again in 35.7. `checked` stays true because the app bucket really was
    /// compared; `system_images_unreadable` and `system_bucket_reason` say why
    /// the rest is empty.
    private func probeCodeIntegrity() -> [String: Any] {
        var result: [String: Any] = [
            "status": "ok",
            "checked": false,
            // Core and ext are the system buckets. On iOS they are structurally
            // unmeasurable; reported as zero-compared with a reason, so the
            // server can tell "nothing to compare" from "compared and clean".
            "core_compared_bytes": 0,
            "core_diff_bytes": 0,
            "diff_bytes": 0,
            "ext_compared_bytes": 0,
            "ext_diff_bytes": 0,
            "ext_libs_diff": 0,
            "app_compared_bytes": 0,
            "app_diff_bytes": 0,
            "app_libs_diff": 0,
            "diffed_libs": "",
            "system_images_unreadable": 0,
            "system_bucket_reason": "dyld_shared_cache_has_no_backing_files",
        ]

        let bundlePath = Bundle.main.bundlePath
        var appCompared = 0
        var appDiff = 0
        var appLibsDiff = 0
        var systemUnreadable = 0
        var diffedLibs: [String] = []
        var imagesCompared = 0
        var segmentCompared = 0
        var segmentDiff = 0

        for index in 0..<_dyld_image_count() {
            guard let namePointer = _dyld_get_image_name(index),
                  let header = _dyld_get_image_header(index) else { continue }
            let path = String(cString: namePointer)

            // Anything outside our own bundle is in the shared cache. Counted,
            // not compared, and never treated as clean.
            guard path.hasPrefix(bundlePath) else {
                systemUnreadable += 1
                continue
            }

            let slide = _dyld_get_image_vmaddr_slide(index)
            guard let span = textSpan(of: header) else { continue }
            guard let onDisk = readFileRange(
                path: path, offset: span.segmentFileOffset, length: span.segmentSize
            ) else {
                // A bundle image we cannot read is also not clean.
                systemUnreadable += 1
                continue
            }

            let liveBase = UnsafeRawPointer(
                bitPattern: UInt(span.segmentVMAddress) + UInt(bitPattern: slide)
            )
            guard let liveBase = liveBase else { continue }

            // One pass over the whole __TEXT segment, attributing each differing
            // byte to __text or to the rest. __text is what gets scored; the
            // remainder - the Mach-O header, __stubs, __cstring, __unwind_info -
            // is reported separately because it has no clean baseline yet. If it
            // measures zero on hardware, the header's unused mach_header_64
            // .reserved field becomes a safe flip target, the direct analogue of
            // the ELF EI_PAD bytes used to close the app bucket on Android
            // (DESIGN.md 30.4). Until then it must not influence a verdict.
            var textDiffering = 0
            var segmentDiffering = 0
            onDisk.withUnsafeBytes { (diskBytes: UnsafeRawBufferPointer) in
                let liveBytes = liveBase.assumingMemoryBound(to: UInt8.self)
                let textStart = span.textOffsetInSegment
                let textEnd = textStart + span.textSize
                for offset in 0..<onDisk.count where liveBytes[offset] != diskBytes[offset] {
                    segmentDiffering += 1
                    if offset >= textStart && offset < textEnd {
                        textDiffering += 1
                    }
                }
            }

            segmentCompared += onDisk.count
            segmentDiff += segmentDiffering

            imagesCompared += 1
            appCompared += span.textSize
            if textDiffering > 0 {
                appDiff += textDiffering
                appLibsDiff += 1
                diffedLibs.append((path as NSString).lastPathComponent)
            }
        }

        // checked means "the app bucket was genuinely compared". If not one
        // bundle image could be read, nothing was measured and saying
        // otherwise would be the exact lie this probe exists to avoid.
        result["checked"] = imagesCompared > 0
        result["app_compared_bytes"] = appCompared
        result["app_diff_bytes"] = appDiff
        result["app_libs_diff"] = appLibsDiff
        result["app_images_compared"] = imagesCompared
        result["system_images_unreadable"] = systemUnreadable
        // Telemetry only. Never scored until it has a hardware baseline.
        result["app_segment_compared_bytes"] = segmentCompared
        result["app_segment_diff_bytes"] = segmentDiff
        result["diffed_libs"] = diffedLibs.joined(separator: ",")
        return result
    }

    private struct TextSpan {
        /// The whole __TEXT segment: file offset 0 through filesize, which is
        /// what is mapped at the image's base address.
        let segmentFileOffset: Int
        let segmentSize: Int
        let segmentVMAddress: UInt64
        /// The __text section, which lies inside that segment. Kept separately
        /// because only this range is scored; the rest of __TEXT is telemetry
        /// until it has a clean baseline on hardware.
        let textOffsetInSegment: Int
        let textSize: Int
    }

    /// Locates the __TEXT segment and the __text section inside it.
    private func textSpan(of header: UnsafePointer<mach_header>) -> TextSpan? {
        let raw = UnsafeRawPointer(header)
        let header64 = raw.assumingMemoryBound(to: mach_header_64.self)
        guard header64.pointee.magic == 0xfeed_facf else { return nil }
        var cursor = raw.advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<header64.pointee.ncmds {
            let command = cursor.assumingMemoryBound(to: load_command.self)
            if command.pointee.cmd == UInt32(LC_SEGMENT_64) {
                let segment = cursor.assumingMemoryBound(to: segment_command_64.self)
                if name(of: segment.pointee.segname) == "__TEXT" {
                    let segmentSize = Int(segment.pointee.filesize)
                    guard segmentSize > 0, segmentSize <= 64 * 1024 * 1024 else { return nil }
                    var section = cursor.advanced(by: MemoryLayout<segment_command_64>.size)
                    for _ in 0..<segment.pointee.nsects {
                        let entry = section.assumingMemoryBound(to: section_64.self)
                        if name(of: entry.pointee.sectname) == "__text" {
                            let textOffset = Int(entry.pointee.offset) - Int(segment.pointee.fileoff)
                            let textSize = Int(entry.pointee.size)
                            guard textOffset >= 0,
                                  textSize > 0,
                                  textOffset + textSize <= segmentSize else { return nil }
                            return TextSpan(
                                segmentFileOffset: Int(segment.pointee.fileoff),
                                segmentSize: segmentSize,
                                segmentVMAddress: segment.pointee.vmaddr,
                                textOffsetInSegment: textOffset,
                                textSize: textSize
                            )
                        }
                        section = section.advanced(by: MemoryLayout<section_64>.size)
                    }
                }
            }
            cursor = cursor.advanced(by: Int(command.pointee.cmdsize))
        }
        return nil
    }

    /// Mach-O stores segment and section names as a fixed 16-byte field that is
    /// NOT necessarily NUL-terminated, so it cannot be read with String(cString:).
    private func name(of field: Any) -> String {
        var bytes: [UInt8] = []
        withUnsafeBytes(of: field) { raw in
            for byte in raw {
                if byte == 0 { break }
                bytes.append(byte)
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private func readFileRange(path: String, offset: Int, length: Int) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: UInt64(offset))
            guard let data = try handle.read(upToCount: length), data.count == length else {
                return nil
            }
            return data
        } catch {
            return nil
        }
    }

    // MARK: - Mach-O and code-signature parsing

    // Integers are assembled byte by byte rather than loaded through a bound
    // pointer: the offsets below are not guaranteed to be naturally aligned,
    // and loadUnaligned(fromByteOffset:as:) is unavailable at our iOS 15.0
    // deployment target.

    private func u32le(_ d: Data, _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= d.count else { return nil }
        return UInt32(d[o]) | (UInt32(d[o + 1]) << 8)
            | (UInt32(d[o + 2]) << 16) | (UInt32(d[o + 3]) << 24)
    }

    private func u32be(_ d: Data, _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= d.count else { return nil }
        return (UInt32(d[o]) << 24) | (UInt32(d[o + 1]) << 16)
            | (UInt32(d[o + 2]) << 8) | UInt32(d[o + 3])
    }

    /// File offset of the 64-bit Mach-O image to inspect, resolving a fat
    /// binary to its arm64 slice. Installed device binaries are thin; fat is
    /// handled so the same code works on a locally built bundle.
    ///
    /// Only MH_MAGIC_64 is accepted. A byte-swapped image would need every
    /// subsequent field swapped too, and silently misparsing one is worse than
    /// reporting that the image was not recognised.
    private func machOSliceOffset(_ d: Data) -> Int? {
        if let magic = u32le(d, 0), magic == 0xfeed_facf { return 0 }

        guard let fat = u32be(d, 0), fat == 0xcafe_babe,
              let count = u32be(d, 4), count < 64 else { return nil }
        let cpuTypeArm64: UInt32 = 0x0100_000c
        for index in 0..<Int(count) {
            let base = 8 + index * 20
            guard let cpu = u32be(d, base), let offset = u32be(d, base + 8) else {
                return nil
            }
            if cpu == cpuTypeArm64,
               let magic = u32le(d, Int(offset)), magic == 0xfeed_facf {
                return Int(offset)
            }
        }
        return nil
    }

    /// Walks the load commands for LC_CODE_SIGNATURE and returns the signature
    /// blob's range. Its dataoff is relative to the start of the slice, so the
    /// slice offset is added back for a fat image.
    private func codeSignatureRange(
        _ d: Data, sliceOffset: Int
    ) -> (offset: Int, size: Int)? {
        guard let commandCount = u32le(d, sliceOffset + 16) else { return nil }
        var cursor = sliceOffset + 32           // sizeof(struct mach_header_64)

        for _ in 0..<Int(commandCount) {
            guard let command = u32le(d, cursor),
                  let commandSize = u32le(d, cursor + 4),
                  commandSize >= 8 else { return nil }

            if command == 0x1d {                // LC_CODE_SIGNATURE
                guard let dataOffset = u32le(d, cursor + 8),
                      let dataSize = u32le(d, cursor + 12) else { return nil }
                let absolute = sliceOffset + Int(dataOffset)
                guard absolute >= 0, absolute + Int(dataSize) <= d.count else {
                    return nil
                }
                return (absolute, Int(dataSize))
            }

            cursor += Int(commandSize)
            if cursor >= d.count { return nil }
        }
        return nil
    }

    /// Parses the embedded signature SuperBlob. The CodeDirectory carries the
    /// signing identifier; the entitlements slot carries an XML plist holding
    /// the team identifier and get-task-allow. Every field in these structures
    /// is big-endian irrespective of the host byte order.
    private func parseEmbeddedSignature(
        _ d: Data, offset: Int, size: Int, into result: inout [String: Any]
    ) {
        guard let magic = u32be(d, offset), magic == 0xfade_0cc0,
              let blobCount = u32be(d, offset + 8), blobCount < 128 else {
            result["signature_parse_error"] = "Not an embedded signature SuperBlob."
            return
        }

        for index in 0..<Int(blobCount) {
            let entry = offset + 12 + index * 8
            guard let slot = u32be(d, entry),
                  let relative = u32be(d, entry + 4) else { return }
            let blob = offset + Int(relative)
            guard blob + 8 <= offset + size else { continue }

            switch slot {
            case 0:                             // CSSLOT_CODEDIRECTORY
                guard let cdMagic = u32be(d, blob), cdMagic == 0xfade_0c02,
                      let flags = u32be(d, blob + 12),
                      let identOffset = u32be(d, blob + 20) else { continue }
                result["code_directory_flags"] = Int(flags)

                let start = blob + Int(identOffset)
                var end = start
                while end < d.count, d[end] != 0 { end += 1 }
                if end > start,
                   let text = String(data: d.subdata(in: start..<end), encoding: .utf8) {
                    result["signing_identifier"] = text
                }

            case 5:                             // CSSLOT_ENTITLEMENTS
                guard let entitlementMagic = u32be(d, blob),
                      entitlementMagic == 0xfade_7171,
                      let length = u32be(d, blob + 4), length > 8 else { continue }
                let start = blob + 8
                let stop = blob + Int(length)
                guard stop <= d.count, start < stop else { continue }

                let object = try? PropertyListSerialization.propertyList(
                    from: d.subdata(in: start..<stop), options: [], format: nil
                )
                if let parsed = object as? [String: Any] {
                    result["team_identifier"] =
                        parsed["com.apple.developer.team-identifier"] as? String ?? ""
                    result["get_task_allow"] =
                        (parsed["get-task-allow"] as? Bool) ?? false
                    result["entitlement_count"] = parsed.count
                }

            default:
                continue
            }
        }
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
        // The Simulator's filesystem is the MAC's filesystem, and macOS really
        // does ship /bin/bash, /bin/sh, /usr/bin/ssh and /usr/sbin/sshd - four
        // entries in the list below. Running this check there produces a
        // confident false positive on a perfectly clean machine, so it is
        // skipped with an explicit reason rather than silently returning empty.
        #if targetEnvironment(simulator)
        return [
            "status": "unsupported",
            "reason": "simulator_filesystem_is_the_host",
            "found_paths": [String](),
        ]
        #else
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
        #endif
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
