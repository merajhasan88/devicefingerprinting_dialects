import Foundation
import LocalAuthentication
import Security

/// Failure carrying the same error-code vocabulary the Android host uses, so
/// Dart sees one contract regardless of platform.
struct InstallationKeyFailure: Error {
    let code: String
    let message: String
}

/// Owns one non-exportable P-256 signing key in the Secure Enclave.
///
/// This is the iOS counterpart of `InstallationKeyManager.kt`. The contract it
/// must honour is fixed by the Dart client (`NativeKeyMetadata.fromPlatform`),
/// which rejects anything that is not an EC P-256 JWK and requires every field
/// below to be present and correctly typed.
///
/// Two properties are load-bearing and must match Android exactly:
///
///   * the payload arrives as base64url TEXT, is base64url-DECODED, and the raw
///     bytes are signed — the server verifies over exactly those bytes;
///   * the signature is ASN.1 DER. `ecdsaSignatureMessageX962SHA256` produces
///     X9.62/DER, which is what `SHA256withECDSA` yields on Android and what
///     PyCryptodome verifies server-side. A raw r||s signature would be
///     rejected.
final class InstallationKeyManager {
    private static let channelKeyVersion = 2
    private static let maxPayloadBytes = 65536

    private let alias: String
    private let tag: Data

    init(bundleIdentifier: String) {
        // Mirrors the Android alias shape so the two platforms are legible
        // side by side in logs and support tickets.
        alias = "\(bundleIdentifier).device_recognition.installation_key.v2"
        tag = Data(alias.utf8)
    }

    // MARK: - Channel operations

    func getOrCreateKey() throws -> [String: Any] {
        var created = false
        var key = try loadKey()

        if key == nil {
            key = try generateKey()
            created = true
        }

        guard let privateKey = key else {
            throw InstallationKeyFailure(
                code: "KEY_NOT_FOUND",
                message: "The iOS installation key could not be created or loaded."
            )
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw InstallationKeyFailure(
                code: "INVALID_PUBLIC_KEY",
                message: "The Secure Enclave did not return a public key."
            )
        }

        var exportError: Unmanaged<CFError>?
        guard let representation =
            SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            throw InstallationKeyFailure(
                code: "INVALID_PUBLIC_KEY",
                message: "The public key could not be exported: \(describe(exportError))"
            )
        }

        // ANSI X9.63 uncompressed point: 0x04 || X(32) || Y(32).
        guard representation.count == 65, representation.first == 0x04 else {
            throw InstallationKeyFailure(
                code: "INVALID_PUBLIC_KEY",
                message: "The public key is not an uncompressed P-256 point."
            )
        }
        let x = representation.subdata(in: 1..<33)
        let y = representation.subdata(in: 33..<65)

        let security = describeSecurity(privateKey)

        return [
            "version": InstallationKeyManager.channelKeyVersion,
            "key_alias": alias,
            "algorithm": "ES256",
            "signature_format": "asn1_der",
            "provider": security.provider,
            "security_level": security.level,
            "hardware_backed": security.hardwareBacked,
            "private_key_exportable": false,
            "created": created,
            "public_key": [
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "x": base64Url(x),
                "y": base64Url(y),
            ],
        ]
    }

    func signPayload(_ payloadBase64Url: String) throws -> String {
        let payload = try decodeBase64Url(payloadBase64Url)
        guard payload.count <= InstallationKeyManager.maxPayloadBytes else {
            throw InstallationKeyFailure(
                code: "PAYLOAD_TOO_LARGE",
                message: "The challenge payload is larger than \(InstallationKeyManager.maxPayloadBytes) bytes."
            )
        }

        guard let privateKey = try loadKey() else {
            throw InstallationKeyFailure(
                code: "KEY_NOT_FOUND",
                message: "The iOS installation key is missing. Restart the app to create a fresh installation identity."
            )
        }

        guard SecKeyIsAlgorithmSupported(
            privateKey, .sign, .ecdsaSignatureMessageX962SHA256
        ) else {
            throw InstallationKeyFailure(
                code: "SIGNING_FAILED",
                message: "The installation key does not support ECDSA-SHA256 signing."
            )
        }

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            payload as CFData,
            &signError
        ) as Data? else {
            throw InstallationKeyFailure(
                code: "SIGNING_FAILED",
                message: "The Secure Enclave could not sign the installation challenge: \(describe(signError))"
            )
        }

        return base64Url(signature)
    }

    @discardableResult
    func deleteKey() throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess { return true }
        if status == errSecItemNotFound { return false }
        throw InstallationKeyFailure(
            code: "KEY_DELETE_FAILED",
            message: "The keychain could not delete the installation key (OSStatus \(status))."
        )
    }

    // MARK: - Key material

    private func loadKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw InstallationKeyFailure(
                code: "KEY_LOOKUP_FAILED",
                message: "The keychain could not load the installation key (OSStatus \(status))."
            )
        }
        guard let result = item, CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw InstallationKeyFailure(
                code: "KEY_LOOKUP_FAILED",
                message: "The keychain returned an item that is not a key."
            )
        }
        // swiftlint:disable:next force_cast
        return (result as! SecKey)
    }

    /// Secure Enclave first, with a graceful fallback — the same shape as the
    /// Android host's StrongBox attempt. The Simulator has no Secure Enclave,
    /// and some configurations refuse a given algorithm, so a failure here must
    /// not leave the app unable to enrol.
    private func generateKey() throws -> SecKey {
        if let key = try? generateKey(useSecureEnclave: true) {
            return key
        }
        // Clear any partial item the failed attempt may have left behind, so
        // the retry is not blocked by a duplicate tag.
        _ = try? deleteKey()
        return try generateKey(useSecureEnclave: false)
    }

    private func generateKey(useSecureEnclave: Bool) throws -> SecKey {
        var privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
        ]

        if useSecureEnclave {
            var accessError: Unmanaged<CFError>?
            // .privateKeyUsage only - no biometric or passcode gate, matching
            // the Android host's setUserAuthenticationRequired(false). The key
            // must be usable unattended for background integrity scans.
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                [.privateKeyUsage],
                &accessError
            ) else {
                throw InstallationKeyFailure(
                    code: "KEY_GENERATION_FAILED",
                    message: "Could not build the Secure Enclave access control: \(describe(accessError))"
                )
            }
            privateKeyAttributes[kSecAttrAccessControl as String] = access
        } else {
            privateKeyAttributes[kSecAttrAccessible as String] =
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            // Best effort on a device without a Secure Enclave. The server is
            // told the truth through security_level/hardware_backed so it can
            // weight the installation accordingly.
            privateKeyAttributes[kSecAttrIsExtractable as String] = false
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateKeyAttributes,
        ]
        if useSecureEnclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw InstallationKeyFailure(
                code: "KEY_GENERATION_FAILED",
                message: useSecureEnclave
                    ? "The Secure Enclave could not create the P-256 installation key: \(describe(error))"
                    : "The keychain could not create the P-256 installation key: \(describe(error))"
            )
        }
        return key
    }

    private func describeSecurity(
        _ key: SecKey
    ) -> (provider: String, level: String, hardwareBacked: Bool) {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any] else {
            return ("Keychain", "unknown", false)
        }
        let tokenID = attributes[kSecAttrTokenID as String] as? String
        if tokenID == (kSecAttrTokenIDSecureEnclave as String) {
            return ("SecureEnclave", "secure_enclave", true)
        }
        return ("Keychain", "software", false)
    }

    // MARK: - Encoding

    private func base64Url(_ value: Data) -> String {
        var text = value.base64EncodedString()
        text = text.replacingOccurrences(of: "+", with: "-")
        text = text.replacingOccurrences(of: "/", with: "_")
        text = text.replacingOccurrences(of: "=", with: "")
        return text
    }

    private func decodeBase64Url(_ value: String) throws -> Data {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw InstallationKeyFailure(
                code: "INVALID_PAYLOAD",
                message: "The challenge payload is empty."
            )
        }
        var text = trimmed
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Restore the padding base64url omits.
        let remainder = text.count % 4
        if remainder > 0 {
            text.append(String(repeating: "=", count: 4 - remainder))
        }
        guard let data = Data(base64Encoded: text) else {
            throw InstallationKeyFailure(
                code: "INVALID_PAYLOAD",
                message: "The challenge payload is not valid base64url."
            )
        }
        return data
    }

    private func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "unknown error" }
        return CFErrorCopyDescription(error) as String? ?? "unknown error"
    }
}

/// Owns the OPTIONAL step-up key (DESIGN.md 51 and 53): a second Secure Enclave
/// P-256 key whose access control demands the device passcode (default) or
/// the current biometric set for EVERY signature.
///
/// The installation key above stays unattended for routine proof of
/// possession; this key approves only sensitive operations, so a compromised
/// app process cannot drive it as a silent signing oracle for them.
///
/// iOS always gets per-use: each signature runs with a fresh `LAContext`, so an
/// earlier authentication is never reused. A windowed mode is not offered here
/// because iOS has no hardware-enforced reuse window for a passcode-gated key,
/// and an app-level "authenticated recently?" check is exactly what DESIGN.md
/// 51.3 rules out.
///
/// The key requires a passcode to exist
/// (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`): without one it cannot
/// be created, and removing the passcode deletes it. The factor is recorded in
/// the key's label at creation so what is reported is what the key enforces.
final class StepUpKeyManager {
    private static let maxPayloadBytes = 65536
    private static let labelPrefix = "stepup:"

    private let alias: String
    private let tag: Data

    init(bundleIdentifier: String) {
        alias = "\(bundleIdentifier).device_recognition.stepup_key.v1"
        tag = Data(alias.utf8)
    }

    // MARK: - Channel operations

    func getOrCreateKey(factor: String) throws -> [String: Any] {
        guard factor == "passcode" || factor == "biometric" else {
            throw InstallationKeyFailure(
                code: "INVALID_ARGUMENT",
                message: "factor must be passcode or biometric."
            )
        }

        var created = false
        var key = try loadKey(context: nil)
        if key == nil {
            try requireFactorAvailable(factor)
            key = try generateKey(factor: factor)
            created = true
        }
        guard let privateKey = key, let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw InstallationKeyFailure(
                code: "STEPUP_KEY_NOT_FOUND",
                message: "The step-up key could not be created or loaded."
            )
        }

        var exportError: Unmanaged<CFError>?
        guard let representation =
            SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data?,
            representation.count == 65, representation.first == 0x04 else {
            throw InstallationKeyFailure(
                code: "INVALID_PUBLIC_KEY",
                message: "The step-up public key is not an uncompressed P-256 point."
            )
        }

        return [
            "key_alias": alias,
            "algorithm": "ES256",
            "signature_format": "asn1_der",
            "provider": "SecureEnclave",
            "security_level": "secure_enclave",
            "hardware_backed": true,
            "private_key_exportable": false,
            "created": created,
            "public_key": [
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "x": base64Url(representation.subdata(in: 1..<33)),
                "y": base64Url(representation.subdata(in: 33..<65)),
            ],
            "auth": [
                "factor": storedFactor() ?? factor,
                "mode": "per_use",
                "window_seconds": 0,
            ] as [String: Any],
        ]
    }

    /// Blocks until the user answers the system prompt, so it must run off the
    /// platform thread (AppDelegate's worker queue).
    func signPayload(_ payloadBase64Url: String, reason: String) throws -> String {
        let payload = try decodeBase64Url(payloadBase64Url)
        guard payload.count <= StepUpKeyManager.maxPayloadBytes else {
            throw InstallationKeyFailure(
                code: "PAYLOAD_TOO_LARGE",
                message: "The step-up payload is larger than \(StepUpKeyManager.maxPayloadBytes) bytes."
            )
        }

        // A fresh context per signature: an already-evaluated context would be
        // reused silently, and per-use is the whole point.
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0

        guard let privateKey = try loadKey(context: context) else {
            throw InstallationKeyFailure(
                code: "STEPUP_KEY_NOT_FOUND",
                message: "No step-up key exists on this installation."
            )
        }

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            payload as CFData,
            &signError
        ) as Data? else {
            throw signFailure(signError?.takeRetainedValue())
        }
        return base64Url(signature)
    }

    @discardableResult
    func deleteKey() throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess { return true }
        if status == errSecItemNotFound { return false }
        throw InstallationKeyFailure(
            code: "KEY_DELETE_FAILED",
            message: "The keychain could not delete the step-up key (OSStatus \(status))."
        )
    }

    // MARK: - Key material

    private func requireFactorAvailable(_ factor: String) throws {
        let context = LAContext()
        var policyError: NSError?
        let policy: LAPolicy = factor == "biometric"
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        if !context.canEvaluatePolicy(policy, error: &policyError) {
            throw InstallationKeyFailure(
                code: factor == "biometric" ? "STEPUP_NO_BIOMETRIC" : "STEPUP_NO_DEVICE_CREDENTIAL",
                message: factor == "biometric"
                    ? "Enrol Touch ID or Face ID to enable biometric step-up."
                    : "Set a device passcode to enable step-up."
            )
        }
    }

    private func generateKey(factor: String) throws -> SecKey {
        let flags: SecAccessControlCreateFlags = factor == "biometric"
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage, .devicePasscode]
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            flags,
            &accessError
        ) else {
            throw InstallationKeyFailure(
                code: "STEPUP_KEY_GENERATION_FAILED",
                message: "Could not build the step-up access control: \(describe(accessError))"
            )
        }

        let privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrLabel as String: StepUpKeyManager.labelPrefix + factor,
            kSecAttrAccessControl as String: access,
        ]
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttributes,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw InstallationKeyFailure(
                code: "STEPUP_KEY_GENERATION_FAILED",
                message: "The Secure Enclave could not create the step-up key: \(describe(error))"
            )
        }
        return key
    }

    private func loadKey(context: LAContext?) throws -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw InstallationKeyFailure(
                code: "KEY_LOOKUP_FAILED",
                message: "The keychain could not load the step-up key (OSStatus \(status))."
            )
        }
        guard let result = item, CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw InstallationKeyFailure(
                code: "KEY_LOOKUP_FAILED",
                message: "The keychain returned an item that is not a key."
            )
        }
        // swiftlint:disable:next force_cast
        return (result as! SecKey)
    }

    private func storedFactor() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnAttributes as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let attributes = item as? [String: Any],
              let label = attributes[kSecAttrLabel as String] as? String,
              label.hasPrefix(StepUpKeyManager.labelPrefix) else {
            return nil
        }
        return String(label.dropFirst(StepUpKeyManager.labelPrefix.count))
    }

    private func signFailure(_ error: CFError?) -> InstallationKeyFailure {
        guard let error = error else {
            return InstallationKeyFailure(
                code: "STEPUP_SIGNING_FAILED",
                message: "The Secure Enclave could not sign with the step-up key."
            )
        }
        let domain = CFErrorGetDomain(error) as String
        let code = CFErrorGetCode(error)
        let text = CFErrorCopyDescription(error) as String? ?? "unknown error"
        let laCancel = [
            LAError.Code.userCancel.rawValue,
            LAError.Code.appCancel.rawValue,
            LAError.Code.systemCancel.rawValue,
        ]
        if (domain == NSOSStatusErrorDomain && code == Int(errSecUserCanceled))
            || (domain == LAErrorDomain && laCancel.contains(code)) {
            return InstallationKeyFailure(
                code: "STEPUP_CANCELLED",
                message: "Step-up authentication was cancelled: \(text)"
            )
        }
        if (domain == NSOSStatusErrorDomain && code == Int(errSecAuthFailed))
            || domain == LAErrorDomain {
            return InstallationKeyFailure(
                code: "STEPUP_AUTH_FAILED",
                message: "Step-up authentication failed: \(text)"
            )
        }
        return InstallationKeyFailure(
            code: "STEPUP_SIGNING_FAILED",
            message: "The Secure Enclave could not sign with the step-up key: \(text)"
        )
    }

    // MARK: - Encoding (mirrors InstallationKeyManager)

    private func base64Url(_ value: Data) -> String {
        var text = value.base64EncodedString()
        text = text.replacingOccurrences(of: "+", with: "-")
        text = text.replacingOccurrences(of: "/", with: "_")
        text = text.replacingOccurrences(of: "=", with: "")
        return text
    }

    private func decodeBase64Url(_ value: String) throws -> Data {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw InstallationKeyFailure(code: "INVALID_PAYLOAD", message: "The step-up payload is empty.")
        }
        var text = trimmed
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = text.count % 4
        if remainder > 0 {
            text.append(String(repeating: "=", count: 4 - remainder))
        }
        guard let data = Data(base64Encoded: text) else {
            throw InstallationKeyFailure(
                code: "INVALID_PAYLOAD",
                message: "The step-up payload is not valid base64url."
            )
        }
        return data
    }

    private func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "unknown error" }
        return CFErrorCopyDescription(error) as String? ?? "unknown error"
    }
}
