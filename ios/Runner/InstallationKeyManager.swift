import Foundation
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
