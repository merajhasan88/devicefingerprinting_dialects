# Key storage, and what each store actually guarantees

The installation key is the whole basis of device binding. A token stolen from one device is useless
on another **only** because the thief cannot produce a signature from the key that stayed behind.
Everything else in the protocol rests on that, so the honesty of these claims matters more than
their strength.

All four stores implement `IInstallationKeyStore`, the .NET analogue of the Flutter client's
`installation_key_v2` method channel, with the same three operations: get-or-create returning a
public JWK, sign returning a DER signature, and delete. **The private key never crosses that
boundary.**

## AndroidKeyStore — `AndroidKeyStoreInstallationKeyStore`

A port of the Kotlin `InstallationKeyManager`. The key is generated inside AndroidKeyStore with
`KeyGenParameterSpec`, purpose `Sign`, digest SHA-256, no user-authentication requirement. The
managed `PrivateKey` is only a handle; Android performs the signing inside the keystore.

StrongBox is attempted first when `FEATURE_STRONGBOX_KEYSTORE` is present, and abandoned quietly on
failure, because some devices advertise StrongBox yet cannot satisfy a particular algorithm and
digest combination. Failing enrolment on those devices would be worse than falling back to the TEE.
`SecurityLevel` reports which one ended up holding the key: `strongbox`,
`trusted_execution_environment`, `secure_hardware` (pre-API-31 devices, where only
`isInsideSecureHardware` is available), or `software`.

JCA's `SHA256withECDSA` already produces ASN.1 DER, so no re-encoding happens on this path and none
should be added.

**Guarantee:** the private key cannot be extracted by the application, by another application, or by
a user with adb access on a non-rooted device. Signing requires the device.

## iOS Secure Enclave — `SecureEnclaveInstallationKeyStore`

The Secure Enclave generates the key inside itself and the keychain stores only a reference, so
there is nothing to export. Accessibility is `AfterFirstUnlockThisDeviceOnly`: usable by a
background app once the device has been unlocked since boot, and excluded from iCloud Keychain and
from encrypted backups. A key that could restore onto a second device would defeat device binding
entirely.

Signing uses `SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256`, which hashes with SHA-256 and
returns an X9.62 ASN.1 DER signature — precisely the encoding the server verifies. A "Digest"
variant would need pre-hashing and a raw variant would produce the wrong encoding.

Devices with no Secure Enclave, and the simulator, fall back to an ordinary keychain key and report
`HardwareBacked = false`, so a caller can see the difference rather than assume it.

**Guarantee:** on Enclave-backed hardware the private key never exists outside the Enclave, in
memory or in any backup.

## Windows CNG — `CngInstallationKeyStore`

Created with `CngExportPolicies.None`, so CNG refuses to export the private key through its own API.
The Microsoft Platform Crypto Provider (TPM) is tried first and the software key storage provider is
the fallback, mirroring the StrongBox pattern. `SecurityLevel` reports `tpm` or `software_ksp`, and
`HardwareBacked` is true only for the former.

`ECDsaCng.SignData`'s two-argument overload returns IEEE P-1363, so this store signs through
`EcdsaSignatureFormat.SignDer` like every other one.

**State this accurately.** A desktop CNG key is *not* equivalent to a phone's keystore key:

- An attacker with administrator rights on the machine can use the key as a signing oracle, and on a
  desktop that is a much more ordinary situation than root on a production handset.
- Without a TPM, the software KSP protects the key with DPAPI — good, but not hardware.
- There is no equivalent of the app sandbox isolating the key from other software on the machine.

What still holds, in both the TPM and the software-KSP case, is the property the protocol depends
on: a token stolen from this machine cannot be replayed from another one, because the signature
cannot be produced there. Use the console/Windows build for protocol testing and for desktop
scenarios where that property is the goal — not as a claim of hardware attestation.

## Software file — `SoftwareInstallationKeyStore`

A P-256 key in a PKCS#8 file. **Protocol testing only.** It is the .NET equivalent of the software
key the Python conformance suite uses and makes exactly the same claim: it proves the wire protocol
and proves nothing about device binding. Copying the file transfers the installation identity with
it, which is the attack the other three stores prevent.

`PrivateKeyExportable` reports `true` and `HardwareBacked` reports `false`. The constructor requires
`acknowledgeNotHardwareBacked: true`, so selecting it is a deliberate, greppable decision at every
call site rather than something that can be inherited from a copied sample.

On .NET 8 and later the key file is chmod 600 on Unix. On .NET 6 there is no managed chmod, so the
file inherits the process umask; that gap is documented rather than papered over with a P/Invoke
that would then need per-OS handling in a store meant only for testing.

## Choosing one

| Situation | Store |
|---|---|
| Android application | `AndroidKeyStoreInstallationKeyStore` |
| iOS application | `SecureEnclaveInstallationKeyStore` |
| Windows desktop application | `CngInstallationKeyStore` |
| CI, protocol testing, a Linux console harness | `SoftwareInstallationKeyStore` |

## The boundary that applies to all of them

From `DESIGN.md`, and unchanged by anything in this SDK: a fully compromised OS can falsify local
measurements and may use a legitimate non-exportable key as a signing oracle. There is deliberately
no Play Integrity, SafetyNet, App Attest or DeviceCheck here — the server, not Google or Apple, owns
the risk score. Without an independent hardware root of trust this is strong risk-based defence in
depth, not perfect attestation. Say so rather than overclaiming.
