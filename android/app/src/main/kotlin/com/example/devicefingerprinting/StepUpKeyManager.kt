// IMPORTANT: Keep this package line identical to your existing MainActivity package.
package com.example.devicefingerprinting

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Owns the OPTIONAL step-up key: a second non-exportable P-256 key in
 * AndroidKeyStore that cannot sign without a device authentication
 * (DESIGN.md 51 and 53).
 *
 * The installation key stays unattended for routine proof of possession. This
 * key approves only sensitive operations, so a compromised app process cannot
 * drive it as a silent signing oracle for them.
 *
 * How tightly the hardware binds the authentication depends on the API level
 * (the owner's "Option 1", DESIGN.md 53):
 *
 *   * Android 11+ (API 30): per-use. Each signature is authorised by its own
 *     BiometricPrompt, device credential (passcode) by default.
 *   * Android 9/10 with the passcode factor: before API 30 Keystore cannot bind
 *     a device credential to one operation, so the key gets a short
 *     hardware-enforced validity window. The plugin still asks for the passcode
 *     before every signature; the window is the backstop, and it is reported to
 *     the server as mode "windowed" so the downgrade is visible, not silent.
 *
 * The factor, mode and window reported to Dart are read back from KeyInfo --
 * what the keystore actually enforces -- rather than echoed from the request.
 */
class StepUpKeyManager(private val context: Context) {
    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val CURVE_NAME = "secp256r1"
        private const val MAX_PAYLOAD_BYTES = 65536
        private const val MAX_WINDOW_SECONDS = 3600
        private const val CONFIRM_CREDENTIAL_REQUEST = 0x5354 // "ST"

        const val FACTOR_PASSCODE = "passcode"
        const val FACTOR_BIOMETRIC = "biometric"
        const val MODE_PER_USE = "per_use"
        const val MODE_WINDOWED = "windowed"

        // Option 1: the hardware window used where per-use passcode is not
        // available (API < 30).
        const val LEGACY_WINDOW_SECONDS = 30
    }

    private class KeyAuth(val factor: String, val mode: String, val windowSeconds: Int)

    private class PendingConfirm(
        val entry: KeyStore.PrivateKeyEntry,
        val payload: ByteArray,
        val done: (Result<String>) -> Unit,
    )

    private val keyAlias: String =
        "${context.packageName}.device_recognition.stepup_key.v1"

    private var pendingConfirm: PendingConfirm? = null

    // MARK: channel operations

    fun getOrCreateKey(factor: String, mode: String, windowSeconds: Int): Map<String, Any> {
        requireSupportedAndroid()
        if (factor != FACTOR_PASSCODE && factor != FACTOR_BIOMETRIC) {
            throw InstallationKeyFailure("INVALID_ARGUMENT", "factor must be passcode or biometric.")
        }
        if (mode != MODE_PER_USE && mode != MODE_WINDOWED) {
            throw InstallationKeyFailure("INVALID_ARGUMENT", "mode must be per_use or windowed.")
        }
        if (mode == MODE_WINDOWED && windowSeconds !in 1..MAX_WINDOW_SECONDS) {
            throw InstallationKeyFailure(
                "INVALID_ARGUMENT",
                "A windowed step-up key needs window_seconds between 1 and $MAX_WINDOW_SECONDS.",
            )
        }
        requireDeviceCredential()
        if (factor == FACTOR_BIOMETRIC && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            throw InstallationKeyFailure(
                "STEPUP_UNSUPPORTED",
                "Biometric step-up needs Android 9 (API 28) or newer.",
            )
        }

        val keyStore = loadKeyStore()
        var created = false
        if (!keyStore.containsAlias(keyAlias)) {
            generateKeyPair(keyStore, factor, mode, windowSeconds)
            created = true
        }
        val entry = privateKeyEntry(keyStore)
        val publicKey = entry.certificate.publicKey as? ECPublicKey
            ?: throw InstallationKeyFailure(
                "INVALID_PUBLIC_KEY",
                "AndroidKeyStore did not return an EC public key for the step-up key.",
            )
        val info = keyInfo(entry)
        val auth = describeAuth(info)
        val security = describeSecurity(info)

        return mapOf(
            "key_alias" to keyAlias,
            "algorithm" to "ES256",
            "signature_format" to "asn1_der",
            "provider" to ANDROID_KEY_STORE,
            "security_level" to security.first,
            "hardware_backed" to security.second,
            "private_key_exportable" to false,
            "created" to created,
            "public_key" to mapOf(
                "kty" to "EC",
                "crv" to "P-256",
                "alg" to "ES256",
                "x" to base64Url(unsignedFixed(publicKey.w.affineX, 32)),
                "y" to base64Url(unsignedFixed(publicKey.w.affineY, 32)),
            ),
            "auth" to mapOf(
                "factor" to auth.factor,
                "mode" to auth.mode,
                "window_seconds" to auth.windowSeconds,
            ),
        )
    }

    /**
     * Prompts for the device authentication, then signs. Must be called on the
     * main thread; [done] is invoked on the main thread exactly once.
     *
     * [configuredMode] is the app's setting. A windowed key the app asked to be
     * per-use (the API < 30 fallback) prompts every time; a key the app asked
     * to be windowed signs without a prompt while its hardware window is open.
     */
    fun sign(
        activity: Activity,
        payloadBase64Url: String,
        reason: String,
        configuredMode: String,
        done: (Result<String>) -> Unit,
    ) {
        try {
            requireSupportedAndroid()
            if (pendingConfirm != null) {
                throw InstallationKeyFailure(
                    "STEPUP_BUSY",
                    "A step-up authentication is already in progress.",
                )
            }
            val payload = decodeBase64Url(payloadBase64Url)
            if (payload.size > MAX_PAYLOAD_BYTES) {
                throw InstallationKeyFailure(
                    "PAYLOAD_TOO_LARGE",
                    "The step-up payload is larger than $MAX_PAYLOAD_BYTES bytes.",
                )
            }
            val keyStore = loadKeyStore()
            if (!keyStore.containsAlias(keyAlias)) {
                throw InstallationKeyFailure(
                    "STEPUP_KEY_NOT_FOUND",
                    "No step-up key exists on this installation.",
                )
            }
            val entry = privateKeyEntry(keyStore)
            val auth = describeAuth(keyInfo(entry))

            if (auth.mode == MODE_PER_USE) {
                val signer = Signature.getInstance("SHA256withECDSA")
                signer.initSign(entry.privateKey)
                authenticateOperation(activity, signer, auth.factor, reason, payload, done)
                return
            }

            if (configuredMode == MODE_WINDOWED) {
                try {
                    done(Result.success(signNow(entry, payload)))
                    return
                } catch (_: UserNotAuthenticatedException) {
                    // The window is closed; authenticate below and sign.
                }
            }
            authenticateThenSign(activity, entry, auth.factor, reason, payload, done)
        } catch (error: KeyPermanentlyInvalidatedException) {
            done(Result.failure(invalidated(error)))
        } catch (error: InstallationKeyFailure) {
            done(Result.failure(error))
        } catch (error: GeneralSecurityException) {
            done(
                Result.failure(
                    InstallationKeyFailure(
                        "STEPUP_SIGNING_FAILED",
                        "AndroidKeyStore could not prepare the step-up signature: ${error.message}",
                        error,
                    ),
                ),
            )
        }
    }

    /** Delivers the legacy confirm-credential result. True if it was ours. */
    fun onActivityResult(requestCode: Int, resultCode: Int): Boolean {
        if (requestCode != CONFIRM_CREDENTIAL_REQUEST) {
            return false
        }
        val pending = pendingConfirm ?: return true
        pendingConfirm = null
        if (resultCode == Activity.RESULT_OK) {
            signAndReport(pending.entry, pending.payload, pending.done)
        } else {
            pending.done(
                Result.failure(
                    InstallationKeyFailure("STEPUP_CANCELLED", "The passcode prompt was cancelled."),
                ),
            )
        }
        return true
    }

    fun deleteKey(): Boolean {
        requireSupportedAndroid()
        val keyStore = loadKeyStore()
        return try {
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
                true
            } else {
                false
            }
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "KEY_DELETE_FAILED",
                "AndroidKeyStore could not delete the step-up key.",
                error,
            )
        }
    }

    // MARK: authentication

    /** Per-use: the prompt authorises this one Signature object. */
    private fun authenticateOperation(
        activity: Activity,
        signer: Signature,
        factor: String,
        reason: String,
        payload: ByteArray,
        done: (Result<String>) -> Unit,
    ) {
        val prompt = buildPrompt(activity, factor, reason, done)
        prompt.authenticate(
            BiometricPrompt.CryptoObject(signer),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authorised = result.cryptoObject?.signature ?: signer
                    try {
                        authorised.update(payload)
                        done(Result.success(base64Url(authorised.sign())))
                    } catch (error: GeneralSecurityException) {
                        done(Result.failure(signingFailed(error)))
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    done(Result.failure(promptError(errorCode, errString)))
                }
            },
        )
    }

    /** Windowed: authenticate first, then sign inside the hardware window. */
    private fun authenticateThenSign(
        activity: Activity,
        entry: KeyStore.PrivateKeyEntry,
        factor: String,
        reason: String,
        payload: ByteArray,
        done: (Result<String>) -> Unit,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val prompt = buildPrompt(activity, factor, reason, done)
            prompt.authenticate(
                CancellationSignal(),
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        signAndReport(entry, payload, done)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        done(Result.failure(promptError(errorCode, errString)))
                    }
                },
            )
            return
        }

        // API < 30: the system confirm-credential screen (PIN / pattern /
        // password). A successful confirmation opens the key's window.
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        @Suppress("DEPRECATION")
        val intent = keyguard?.createConfirmDeviceCredentialIntent(
            "Approve sensitive operation",
            reason,
        ) ?: throw InstallationKeyFailure(
            "STEPUP_NO_DEVICE_CREDENTIAL",
            "Set a screen lock (PIN, pattern or password) to use step-up.",
        )
        pendingConfirm = PendingConfirm(entry, payload, done)
        activity.startActivityForResult(intent, CONFIRM_CREDENTIAL_REQUEST)
    }

    private fun buildPrompt(
        activity: Activity,
        factor: String,
        reason: String,
        done: (Result<String>) -> Unit,
    ): BiometricPrompt {
        val builder = BiometricPrompt.Builder(activity)
            .setTitle("Approve sensitive operation")
            .setDescription(reason)
        val allowsCredential = factor == FACTOR_PASSCODE &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(
                if (allowsCredential) {
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
                } else {
                    BiometricManager.Authenticators.BIOMETRIC_STRONG
                },
            )
        }
        if (!allowsCredential) {
            // A biometric-only prompt must offer its own way out; a
            // device-credential prompt must not (the system provides one).
            builder.setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                done(
                    Result.failure(
                        InstallationKeyFailure("STEPUP_CANCELLED", "The biometric prompt was cancelled."),
                    ),
                )
            }
        }
        return builder.build()
    }

    private fun promptError(errorCode: Int, errString: CharSequence): InstallationKeyFailure {
        val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
            errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
        return InstallationKeyFailure(
            if (cancelled) "STEPUP_CANCELLED" else "STEPUP_AUTH_FAILED",
            "Step-up authentication did not complete: $errString (code $errorCode)",
        )
    }

    // MARK: signing

    private fun signNow(entry: KeyStore.PrivateKeyEntry, payload: ByteArray): String {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(entry.privateKey)
        signer.update(payload)
        return base64Url(signer.sign())
    }

    private fun signAndReport(
        entry: KeyStore.PrivateKeyEntry,
        payload: ByteArray,
        done: (Result<String>) -> Unit,
    ) {
        try {
            done(Result.success(signNow(entry, payload)))
        } catch (error: KeyPermanentlyInvalidatedException) {
            done(Result.failure(invalidated(error)))
        } catch (error: UserNotAuthenticatedException) {
            done(
                Result.failure(
                    InstallationKeyFailure(
                        "STEPUP_AUTH_FAILED",
                        "The keystore did not accept the authentication for the step-up key.",
                        error,
                    ),
                ),
            )
        } catch (error: GeneralSecurityException) {
            done(Result.failure(signingFailed(error)))
        }
    }

    private fun invalidated(error: Throwable) = InstallationKeyFailure(
        "STEPUP_KEY_INVALIDATED",
        "The step-up key was invalidated (the screen lock or enrolled biometrics changed). " +
            "Re-enrol the installation to get a new one.",
        error,
    )

    private fun signingFailed(error: Throwable) = InstallationKeyFailure(
        "STEPUP_SIGNING_FAILED",
        "AndroidKeyStore could not sign with the step-up key: ${error.message}",
        error,
    )

    // MARK: key material

    private fun generateKeyPair(
        keyStore: KeyStore,
        factor: String,
        mode: String,
        windowSeconds: Int,
    ) {
        val canTryStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (canTryStrongBox) {
            try {
                generateKeyPair(factor, mode, windowSeconds, preferStrongBox = true)
                return
            } catch (_: Exception) {
                // Same fallback as the installation key: remove any partial
                // alias and retry with the regular AndroidKeyStore provider.
                try {
                    if (keyStore.containsAlias(keyAlias)) {
                        keyStore.deleteEntry(keyAlias)
                    }
                } catch (_: Exception) {
                }
            }
        }
        generateKeyPair(factor, mode, windowSeconds, preferStrongBox = false)
    }

    private fun generateKeyPair(
        factor: String,
        mode: String,
        windowSeconds: Int,
        preferStrongBox: Boolean,
    ) {
        try {
            val builder = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE_NAME))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    if (mode == MODE_WINDOWED) windowSeconds else 0,
                    if (factor == FACTOR_BIOMETRIC) {
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    } else {
                        KeyProperties.AUTH_DEVICE_CREDENTIAL
                    },
                )
            } else if (factor == FACTOR_PASSCODE) {
                // Option 1 fallback: no per-operation device credential before
                // API 30, so a short hardware window is the strongest binding.
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(
                    if (mode == MODE_WINDOWED) windowSeconds else LEGACY_WINDOW_SECONDS,
                )
            } else if (mode == MODE_WINDOWED) {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(windowSeconds)
            }
            // else: biometric per-use before API 30 keeps the default (-1),
            // which demands a biometric for every operation.

            if (factor == FACTOR_BIOMETRIC && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && preferStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }

            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEY_STORE,
            )
            generator.initialize(builder.build())
            generator.generateKeyPair()
        } catch (error: Exception) {
            throw InstallationKeyFailure(
                "STEPUP_KEY_GENERATION_FAILED",
                "AndroidKeyStore could not create the step-up key: ${error.message}",
                error,
            )
        }
    }

    private fun requireSupportedAndroid() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            throw InstallationKeyFailure(
                "UNSUPPORTED_ANDROID_VERSION",
                "Step-up requires Android 6.0 (API 23) or newer.",
            )
        }
    }

    private fun requireDeviceCredential() {
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        if (keyguard == null || !keyguard.isDeviceSecure) {
            throw InstallationKeyFailure(
                "STEPUP_NO_DEVICE_CREDENTIAL",
                "Set a screen lock (PIN, pattern or password) to enable step-up.",
            )
        }
    }

    private fun loadKeyStore(): KeyStore {
        try {
            return KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure("KEYSTORE_UNAVAILABLE", "AndroidKeyStore is unavailable.", error)
        }
    }

    private fun privateKeyEntry(keyStore: KeyStore): KeyStore.PrivateKeyEntry {
        try {
            return keyStore.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry
                ?: throw InstallationKeyFailure(
                    "STEPUP_KEY_NOT_FOUND",
                    "The step-up key entry is missing or has the wrong type.",
                )
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "KEY_LOOKUP_FAILED",
                "AndroidKeyStore could not load the step-up key.",
                error,
            )
        }
    }

    private fun keyInfo(entry: KeyStore.PrivateKeyEntry): KeyInfo {
        try {
            val keyFactory = KeyFactory.getInstance(entry.privateKey.algorithm, ANDROID_KEY_STORE)
            return keyFactory.getKeySpec(entry.privateKey, KeyInfo::class.java)
        } catch (error: GeneralSecurityException) {
            throw InstallationKeyFailure(
                "KEY_LOOKUP_FAILED",
                "AndroidKeyStore could not describe the step-up key.",
                error,
            )
        }
    }

    /** What the keystore enforces for this key, read back from KeyInfo. */
    private fun describeAuth(info: KeyInfo): KeyAuth {
        val duration = info.userAuthenticationValidityDurationSeconds
        val mode = if (duration > 0) MODE_WINDOWED else MODE_PER_USE
        val factor = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (info.userAuthenticationType and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0) {
                FACTOR_PASSCODE
            } else {
                FACTOR_BIOMETRIC
            }
        } else {
            // KeyInfo has no auth type before API 30. A per-use key can then
            // only be unlocked by a biometric; a windowed key by any lock-screen
            // authentication, and the plugin prompts for the passcode.
            if (mode == MODE_PER_USE) FACTOR_BIOMETRIC else FACTOR_PASSCODE
        }
        return KeyAuth(factor, mode, if (duration > 0) duration else 0)
    }

    private fun describeSecurity(info: KeyInfo): Pair<String, Boolean> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox" to true
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trusted_execution_environment" to true
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software" to false
                else -> "unknown" to false
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "secure_hardware" to true else "software" to false
        }
    }

    // MARK: encoding (mirrors InstallationKeyManager)

    private fun unsignedFixed(value: BigInteger, size: Int): ByteArray {
        var raw = value.toByteArray()
        if (raw.size == size + 1 && raw[0] == 0.toByte()) {
            raw = raw.copyOfRange(1, raw.size)
        }
        if (raw.size > size) {
            throw InstallationKeyFailure("INVALID_PUBLIC_KEY", "The EC coordinate is larger than P-256 permits.")
        }
        return ByteArray(size).also { output ->
            System.arraycopy(raw, 0, output, size - raw.size, raw.size)
        }
    }

    private fun base64Url(value: ByteArray): String {
        return Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun decodeBase64Url(value: String): ByteArray {
        if (value.isBlank()) {
            throw InstallationKeyFailure("INVALID_PAYLOAD", "The step-up payload is empty.")
        }
        return try {
            Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (error: IllegalArgumentException) {
            throw InstallationKeyFailure("INVALID_PAYLOAD", "The step-up payload is not valid base64url.", error)
        }
    }
}
