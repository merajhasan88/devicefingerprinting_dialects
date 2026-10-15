// Device trust client: installation identity, proof of possession, native
// integrity collection, and the boundary tests that exercise them. This is the
// reference client implementation that the Dart, .NET and Python SDKs derive
// from.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:android_id/android_id.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:uuid/uuid.dart';

// The endpoint is supplied at build time and has no default, so a build can
// never silently point at someone else's environment:
//   flutter run --dart-define=API_BASE_URL=https://<host>
const String apiBaseUrl = String.fromEnvironment('API_BASE_URL');

const String injectedStolenRefreshToken = String.fromEnvironment(
  'STOLEN_REFRESH_TOKEN',
  defaultValue: '',
);

const String injectedStolenAccessToken = String.fromEnvironment(
  'STOLEN_ACCESS_TOKEN',
  defaultValue: '',
);

// Step-up for sensitive operations (DESIGN.md 51 and 53). Optional: an
// integrating app opts in; this lab build enables it so the flow can be
// tested. The factor, mode and window follow the DBA's policy, read from
// GET /v1/policy/step-up (DESIGN.md 79); these build values are only the
// fallback when the server cannot be asked.
//   --dart-define=STEPUP_ENABLED=false
//   --dart-define=STEPUP_FACTOR=biometric
//   --dart-define=STEPUP_MODE=windowed --dart-define=STEPUP_WINDOW_SECONDS=60
const bool stepUpEnabled =
    bool.fromEnvironment('STEPUP_ENABLED', defaultValue: true);
const String stepUpFactor =
    String.fromEnvironment('STEPUP_FACTOR', defaultValue: 'passcode');
const String stepUpMode =
    String.fromEnvironment('STEPUP_MODE', defaultValue: 'per_use');
const int stepUpWindowSeconds =
    int.fromEnvironment('STEPUP_WINDOW_SECONDS', defaultValue: 0);

// Optional measurements this app's developers allow (DESIGN.md 80). Each is
// collected only when the server's DBA also asks for it (optional_measurements)
// -- two keys, because each identifies a person's phone or network. Off unless
// a build turns it on:
//   --dart-define=MEASURE_LOCAL_ADDRESSES=true   (the phone's own IP addresses)
// and, from DESIGN.md 82 (Android collector 5, iOS collector 4):
//   --dart-define=MEASURE_ACCESSIBILITY=true        (Accessibility services, keyboard)
//   --dart-define=MEASURE_NOTIFICATION_ACCESS=true  (apps that read notifications)
//   --dart-define=MEASURE_OTHER_ACCESS=true         (device admins, remote-control apps)
//   --dart-define=MEASURE_SCREEN_CAPTURE=true       (screen recorded, cast or mirrored)
//   --dart-define=MEASURE_LOCATION=true             (the last known location)
//   --dart-define=MEASURE_MOCK_LOCATION=true        (whether it was simulated)
// The two location measurements also need the person's OS permission, which
// this app asks for only from its "Allow location" button.
const bool measureLocalAddresses =
    bool.fromEnvironment('MEASURE_LOCAL_ADDRESSES', defaultValue: false);
const bool measureAccessibility =
    bool.fromEnvironment('MEASURE_ACCESSIBILITY', defaultValue: false);
const bool measureNotificationAccess =
    bool.fromEnvironment('MEASURE_NOTIFICATION_ACCESS', defaultValue: false);
const bool measureOtherAccess =
    bool.fromEnvironment('MEASURE_OTHER_ACCESS', defaultValue: false);
const bool measureScreenCapture =
    bool.fromEnvironment('MEASURE_SCREEN_CAPTURE', defaultValue: false);
const bool measureLocation =
    bool.fromEnvironment('MEASURE_LOCATION', defaultValue: false);
const bool measureMockLocation =
    bool.fromEnvironment('MEASURE_MOCK_LOCATION', defaultValue: false);
const List<String> enabledMeasurements = <String>[
  if (measureLocalAddresses) 'local_addresses',
  if (measureAccessibility) 'accessibility',
  if (measureNotificationAccess) 'notification_access',
  if (measureOtherAccess) 'other_access',
  if (measureScreenCapture) 'screen_capture',
  if (measureLocation) 'location',
  if (measureMockLocation) 'mock_location',
];

const Duration _networkTimeout = Duration(seconds: 15);

class NativeKeyException implements Exception {
  NativeKeyException(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => '$message [$code]';
}

class NativeKeyMetadata {
  NativeKeyMetadata({
    required this.publicKey,
    required this.algorithm,
    required this.keyAlias,
    required this.provider,
    required this.securityLevel,
    required this.hardwareBacked,
    required this.privateKeyExportable,
    required this.signatureFormat,
    required this.created,
  });

  final Map<String, dynamic> publicKey;
  final String algorithm;
  final String keyAlias;
  final String provider;
  final String securityLevel;
  final bool hardwareBacked;
  final bool privateKeyExportable;
  final String signatureFormat;
  final bool created;

  factory NativeKeyMetadata.fromPlatform(Map<String, dynamic> value) {
    final Object? rawPublicKey = value['public_key'];
    if (rawPublicKey is! Map) {
      throw const FormatException(
        'The native key provider returned no public key.',
      );
    }
    final Map<String, dynamic> publicKey =
        Map<String, dynamic>.from(rawPublicKey);

    String requiredString(String field) {
      final Object? item = value[field];
      if (item is! String || item.isEmpty) {
        throw FormatException(
          'The native key provider returned an invalid $field.',
        );
      }
      return item;
    }

    bool requiredBool(String field) {
      final Object? item = value[field];
      if (item is! bool) {
        throw FormatException(
          'The native key provider returned an invalid $field.',
        );
      }
      return item;
    }

    if (publicKey['kty'] != 'EC' ||
        publicKey['crv'] != 'P-256' ||
        publicKey['alg'] != 'ES256' ||
        publicKey['x'] is! String ||
        publicKey['y'] is! String) {
      throw const FormatException(
        'The native key provider did not return an EC P-256 public JWK.',
      );
    }

    return NativeKeyMetadata(
      publicKey: publicKey,
      algorithm: requiredString('algorithm'),
      keyAlias: requiredString('key_alias'),
      provider: requiredString('provider'),
      securityLevel: requiredString('security_level'),
      hardwareBacked: requiredBool('hardware_backed'),
      privateKeyExportable: requiredBool('private_key_exportable'),
      signatureFormat: requiredString('signature_format'),
      created: requiredBool('created'),
    );
  }
}

class NativeInstallationKey {
  static const MethodChannel _channel = MethodChannel(
    'devicefingerprinting/installation_key_v2',
  );

  Future<NativeKeyMetadata> getOrCreateKey() async {
    try {
      final Map<String, dynamic>? value =
          await _channel.invokeMapMethod<String, dynamic>('getOrCreateKey');
      if (value == null) {
        throw NativeKeyException(
          'EMPTY_NATIVE_RESPONSE',
          'The native key provider returned no key metadata.',
        );
      }
      return NativeKeyMetadata.fromPlatform(value);
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_KEY_PLUGIN_MISSING',
        'The Android/iOS installation-key channel is not registered. '
            'Install the supplied native host code and perform a full rebuild.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native key provider failed.',
      );
    }
  }

  Future<String> signPayload(String payloadBase64Url) async {
    try {
      final String? signature = await _channel.invokeMethod<String>(
        'sign',
        <String, dynamic>{'payload': payloadBase64Url},
      );
      if (signature == null || signature.isEmpty) {
        throw NativeKeyException(
          'EMPTY_NATIVE_SIGNATURE',
          'The native key provider returned no signature.',
        );
      }
      return signature;
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_KEY_PLUGIN_MISSING',
        'The Android/iOS installation-key channel is not registered.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native key provider could not sign the challenge.',
      );
    }
  }

  Future<void> deleteKey() async {
    try {
      await _channel.invokeMethod<bool>('deleteKey');
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_KEY_PLUGIN_MISSING',
        'The Android/iOS installation-key channel is not registered.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native installation key could not be deleted.',
      );
    }
  }
}

/// The optional step-up key as the native side reports it. [factor], [mode]
/// and [windowSeconds] describe what the platform keystore actually enforces
/// (read back from KeyInfo on Android, from the key's label on iOS), which on
/// Android 9/10 is a short hardware window rather than per-use.
class StepUpKeyMetadata {
  StepUpKeyMetadata({
    required this.publicKey,
    required this.factor,
    required this.mode,
    required this.windowSeconds,
    required this.securityLevel,
    required this.hardwareBacked,
    required this.created,
  });

  final Map<String, dynamic> publicKey;
  final String factor;
  final String mode;
  final int windowSeconds;
  final String securityLevel;
  final bool hardwareBacked;
  final bool created;

  Map<String, dynamic> get authJson => <String, dynamic>{
        'factor': factor,
        'mode': mode,
        'window_seconds': windowSeconds,
      };

  String get description => mode == 'per_use'
      ? '$factor, per-use'
      : '$factor, ${windowSeconds}s hardware window';

  /// RFC 7638 thumbprint, the same form the server derives from the JWK.
  String get thumbprint => crypto.sha256
      .convert(utf8.encode(jsonEncode(<String, dynamic>{
        'crv': publicKey['crv'],
        'kty': 'EC',
        'x': publicKey['x'],
        'y': publicKey['y'],
      })))
      .toString();

  factory StepUpKeyMetadata.fromPlatform(Map<String, dynamic> value) {
    final Object? rawPublicKey = value['public_key'];
    final Object? rawAuth = value['auth'];
    if (rawPublicKey is! Map || rawAuth is! Map) {
      throw const FormatException(
        'The native step-up key provider returned no public key or auth.',
      );
    }
    final Map<String, dynamic> publicKey =
        Map<String, dynamic>.from(rawPublicKey);
    final Map<String, dynamic> auth = Map<String, dynamic>.from(rawAuth);
    if (publicKey['kty'] != 'EC' ||
        publicKey['crv'] != 'P-256' ||
        publicKey['alg'] != 'ES256' ||
        publicKey['x'] is! String ||
        publicKey['y'] is! String) {
      throw const FormatException(
        'The native step-up key provider did not return an EC P-256 public JWK.',
      );
    }
    final Object? factor = auth['factor'];
    final Object? mode = auth['mode'];
    final Object? window = auth['window_seconds'];
    if (factor is! String || mode is! String || window is! int) {
      throw const FormatException(
        'The native step-up key provider returned an invalid auth description.',
      );
    }
    return StepUpKeyMetadata(
      publicKey: publicKey,
      factor: factor,
      mode: mode,
      windowSeconds: window,
      securityLevel: value['security_level'] as String? ?? 'unknown',
      hardwareBacked: value['hardware_backed'] == true,
      created: value['created'] == true,
    );
  }
}

/// The DBA's step-up policy as the server states it (GET /v1/policy/step-up,
/// DESIGN.md 79), or the build's STEPUP_* values when the server could not
/// be asked ([fromServer] false; the method is then unknown until sign-in).
class StepUpPolicy {
  const StepUpPolicy({
    required this.method,
    required this.factor,
    required this.mode,
    required this.windowSeconds,
    required this.fromServer,
  });

  static const StepUpPolicy buildFallback = StepUpPolicy(
    method: null,
    factor: stepUpFactor,
    mode: stepUpMode,
    windowSeconds: stepUpWindowSeconds,
    fromServer: false,
  );

  final String? method;
  final String factor;
  final String mode;
  final int windowSeconds;
  final bool fromServer;

  factory StepUpPolicy.fromServer(Map<String, dynamic> value) {
    final Object? method = value['method'];
    final Object? factor = value['factor'];
    final Object? mode = value['mode'];
    final Object? window = value['window_seconds'];
    if (method is! String ||
        (factor != 'passcode' && factor != 'biometric') ||
        (mode != 'per_use' && mode != 'windowed') ||
        window is! int ||
        window < 0 ||
        window > 3600 ||
        (mode == 'windowed' && window < 1)) {
      throw const FormatException(
        'The server returned a step-up policy this app cannot follow.',
      );
    }
    return StepUpPolicy(
      method: method,
      factor: factor as String,
      mode: mode as String,
      windowSeconds: window,
      fromServer: true,
    );
  }

  /// Whether the screen-lock key takes part in a step-up at all: under the
  /// app PIN alone it does not, so its factor is not yet a problem.
  bool get usesScreenLock => method != 'app_pin';

  /// The key satisfies this policy: the same factor (the server refuses any
  /// other), and a per-use key or a window no longer than the policy's. A
  /// per-use key satisfies a windowed policy.
  bool accepts(StepUpKeyMetadata key) =>
      key.factor == factor &&
      (key.mode == 'per_use' ||
          (mode == 'windowed' && key.windowSeconds <= windowSeconds));

  String get description =>
      '${method ?? 'method unknown'}; key $factor, '
      '${mode == 'per_use' ? 'per-use' : '${windowSeconds}s window'}'
      '${fromServer ? '' : ' (build fallback)'}';
}

class NativeStepUpKey {
  static const MethodChannel _channel = MethodChannel(
    'devicefingerprinting/stepup_key_v1',
  );

  /// The deployment's mode, which decides whether a windowed key first tries
  /// to sign inside an open hardware window. Set from the server's policy.
  String configuredMode = stepUpMode;

  /// Returns the existing key as the keystore enforces it, or creates one
  /// with these values: an existing key is never changed, so a caller that
  /// needs other values deletes it first.
  Future<StepUpKeyMetadata> getOrCreateKey({
    String factor = stepUpFactor,
    String mode = stepUpMode,
    int windowSeconds = stepUpWindowSeconds,
  }) async {
    try {
      final Map<String, dynamic>? value =
          await _channel.invokeMapMethod<String, dynamic>(
        'getOrCreateKey',
        <String, dynamic>{
          'factor': factor,
          'mode': mode,
          'window_seconds': windowSeconds,
        },
      );
      if (value == null) {
        throw NativeKeyException(
          'EMPTY_NATIVE_RESPONSE',
          'The native step-up key provider returned no key metadata.',
        );
      }
      return StepUpKeyMetadata.fromPlatform(value);
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_STEPUP_PLUGIN_MISSING',
        'The step-up key channel is not registered in this native build.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native step-up key provider failed.',
      );
    }
  }

  /// Shows the system passcode (or biometric) prompt and completes when the
  /// user answers it. A cancelled prompt is STEPUP_CANCELLED.
  Future<String> sign(String payloadBase64Url, {required String reason}) async {
    try {
      final String? signature = await _channel.invokeMethod<String>(
        'sign',
        <String, dynamic>{
          'payload': payloadBase64Url,
          'reason': reason,
          'mode': configuredMode,
        },
      );
      if (signature == null || signature.isEmpty) {
        throw NativeKeyException(
          'EMPTY_NATIVE_SIGNATURE',
          'The step-up key returned no signature.',
        );
      }
      return signature;
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_STEPUP_PLUGIN_MISSING',
        'The step-up key channel is not registered in this native build.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The step-up key could not sign.',
      );
    }
  }

  Future<void> deleteKey() async {
    try {
      await _channel.invokeMethod<bool>('deleteKey');
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_STEPUP_PLUGIN_MISSING',
        'The step-up key channel is not registered in this native build.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The step-up key could not be deleted.',
      );
    }
  }
}

class NativeIntegrityCollector {
  static const MethodChannel _channel = MethodChannel(
    'devicefingerprinting/integrity_v1',
  );

  Future<Map<String, dynamic>> collect({
    required List<String> requiredProbes,
    required String challengeNonce,
    String? testFixture,
    List<String> optionalProbes = const <String>[],
  }) async {
    try {
      final Map<String, dynamic>? value =
          await _channel.invokeMapMethod<String, dynamic>(
        'collect',
        <String, dynamic>{
          'required_probes': requiredProbes,
          'challenge_nonce': challengeNonce,
          // What the server asks for and what this app allows; the native
          // collector measures only what is in both (DESIGN.md 80).
          'optional_probes': optionalProbes,
          'enabled_measurements': enabledMeasurements,
          if (testFixture != null && testFixture.isNotEmpty)
            'integrity_test_fixture': testFixture,
        },
      );
      if (value == null) {
        throw NativeKeyException(
          'EMPTY_INTEGRITY_RESPONSE',
          'The native integrity collector returned no measurements.',
        );
      }
      return value;
    } on MissingPluginException {
      throw NativeKeyException(
        'NATIVE_INTEGRITY_PLUGIN_MISSING',
        'The Android/iOS integrity channel is not registered. Install the supplied native host code and perform a full rebuild.',
      );
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The native integrity collector failed.',
      );
    }
  }

  /// Asks the person for the OS location permission (DESIGN.md 82) and
  /// returns what the app now holds: precise, approximate or none. Only the
  /// app asks, from its own screen; a scan never prompts.
  Future<String> requestLocationPermission() async {
    try {
      return await _channel.invokeMethod<String>('requestLocationPermission') ??
          'none';
    } on PlatformException catch (error) {
      throw NativeKeyException(
        error.code,
        error.message ?? 'The location permission request failed.',
      );
    }
  }
}

/// Protects the app's window while a secret is typed (DESIGN.md 82). Android:
/// no screenshots, recordings or casts of the window, other apps' windows not
/// drawn over it (Android 12 and later), and touches that passed through
/// another app's window dropped. iOS cannot block screenshots; it covers the
/// window while the screen is recorded or mirrored. Returns what applied; an
/// older native host answers nothing, and the entry stays usable.
class SecureScreen {
  static const MethodChannel _channel = MethodChannel(
    'devicefingerprinting/secure_screen_v1',
  );

  static Future<Map<String, dynamic>> protect(bool on) async {
    try {
      return await _channel.invokeMapMethod<String, dynamic>(
            'protect',
            <String, dynamic>{'on': on},
          ) ??
          const <String, dynamic>{};
    } on MissingPluginException {
      return const <String, dynamic>{};
    } on PlatformException {
      return const <String, dynamic>{};
    }
  }
}

class ApiException implements Exception {
  ApiException(
    this.message, {
    this.statusCode,
    this.code,
    this.details,
  });

  final String message;
  final int? statusCode;
  final String? code;
  final Map<String, dynamic>? details;

  @override
  String toString() => message;
}

class InstallationIdentity {
  InstallationIdentity({
    required this.installationId,
    required this.nativeKey,
    required this.metadata,
  });

  final String installationId;
  final NativeInstallationKey nativeKey;
  final NativeKeyMetadata metadata;

  Map<String, dynamic> get publicKeyJson => metadata.publicKey;
  String get algorithm => metadata.algorithm;
  String get keyAlias => metadata.keyAlias;
  String get provider => metadata.provider;
  String get securityLevel => metadata.securityLevel;
  bool get hardwareBacked => metadata.hardwareBacked;
  bool get privateKeyExportable => metadata.privateKeyExportable;
  String get signatureFormat => metadata.signatureFormat;
  bool get createdThisLaunch => metadata.created;

  String get keyThumbprint {
    // RFC 7638 canonical member order for an EC public JWK.
    final String canonical = jsonEncode(<String, dynamic>{
      'crv': publicKeyJson['crv'],
      'kty': 'EC',
      'x': publicKeyJson['x'],
      'y': publicKeyJson['y'],
    });
    return crypto.sha256.convert(utf8.encode(canonical)).toString();
  }

  Future<String> signPayload(String payloadBase64Url) {
    return nativeKey.signPayload(payloadBase64Url);
  }

  InstallationIdentity withInstallationId(String canonicalInstallationId) {
    return InstallationIdentity(
      installationId: canonicalInstallationId,
      nativeKey: nativeKey,
      metadata: metadata,
    );
  }
}

class RegistrationState {
  RegistrationState({
    required this.installationId,
    required this.deviceId,
    required this.keyThumbprint,
    required this.keyAlgorithm,
    required this.method,
    required this.confidence,
    required this.isReinstallCorrelation,
    this.stepupKeyRegistered = false,
    this.stepupKeyMatches,
    this.stepupKeyAuth,
    this.stepupPolicyDowngrade,
  });

  final String installationId;
  final String deviceId;
  final String keyThumbprint;
  final String keyAlgorithm;
  final String method;
  final String confidence;
  final bool isReinstallCorrelation;

  // The server's view of the step-up key. A step-up key binds only when the
  // installation is first registered; matches is null when none was offered.
  final bool stepupKeyRegistered;
  final bool? stepupKeyMatches;
  final Map<String, dynamic>? stepupKeyAuth;
  final bool? stepupPolicyDowngrade;

  static Map<String, dynamic>? _optionalMap(Object? value) =>
      value is Map ? Map<String, dynamic>.from(value) : null;

  factory RegistrationState.fromJson(Map<String, dynamic> value) {
    final Map<String, dynamic> recognition =
        Map<String, dynamic>.from(value['recognition'] as Map);
    return RegistrationState(
      installationId: value['installation_id'] as String,
      deviceId: value['device_id'] as String,
      keyThumbprint: value['key_thumbprint'] as String,
      keyAlgorithm: value['key_algorithm'] as String? ?? 'unknown',
      method: recognition['method'] as String,
      confidence: recognition['confidence'] as String,
      isReinstallCorrelation:
          recognition['is_reinstall_correlation'] as bool? ?? false,
      stepupKeyRegistered: value['stepup_key_registered'] as bool? ?? false,
      stepupKeyMatches: value['stepup_key_matches'] as bool?,
      stepupKeyAuth: _optionalMap(value['stepup_key_auth']),
      stepupPolicyDowngrade: value['stepup_policy_downgrade'] as bool?,
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'installation_id': installationId,
        'device_id': deviceId,
        'key_thumbprint': keyThumbprint,
        'key_algorithm': keyAlgorithm,
        'method': method,
        'confidence': confidence,
        'is_reinstall_correlation': isReinstallCorrelation,
        'stepup_key_registered': stepupKeyRegistered,
        'stepup_key_matches': stepupKeyMatches,
        'stepup_key_auth': stepupKeyAuth,
        'stepup_policy_downgrade': stepupPolicyDowngrade,
      };

  factory RegistrationState.fromStoredJson(Map<String, dynamic> value) {
    return RegistrationState(
      installationId: value['installation_id'] as String,
      deviceId: value['device_id'] as String,
      keyThumbprint: value['key_thumbprint'] as String,
      keyAlgorithm: value['key_algorithm'] as String? ?? 'unknown',
      method: value['method'] as String,
      confidence: value['confidence'] as String,
      isReinstallCorrelation:
          value['is_reinstall_correlation'] as bool? ?? false,
      stepupKeyRegistered: value['stepup_key_registered'] as bool? ?? false,
      stepupKeyMatches: value['stepup_key_matches'] as bool?,
      stepupKeyAuth: _optionalMap(value['stepup_key_auth']),
      stepupPolicyDowngrade: value['stepup_policy_downgrade'] as bool?,
    );
  }
}

class IntegrityRiskReason {
  IntegrityRiskReason({
    required this.code,
    required this.points,
    required this.message,
    required this.hard,
  });

  final String code;
  final int points;
  final String message;
  final bool hard;

  factory IntegrityRiskReason.fromJson(Map<String, dynamic> value) {
    return IntegrityRiskReason(
      code: value['code'] as String? ?? 'unknown',
      points: (value['points'] as num?)?.toInt() ?? 0,
      message: value['message'] as String? ?? '',
      hard: value['hard'] as bool? ?? false,
    );
  }
}

class IntegrityDecision {
  IntegrityDecision({
    required this.reportId,
    required this.score,
    required this.verdict,
    required this.hardBlock,
    required this.reasons,
    required this.mode,
    required this.freshForSeconds,
    required this.remoteAttestation,
    required this.createdAt,
  });

  final String reportId;
  final int score;
  final String verdict;
  final bool hardBlock;
  final List<IntegrityRiskReason> reasons;
  final String mode;
  final int freshForSeconds;
  final String remoteAttestation;
  final String createdAt;

  factory IntegrityDecision.fromJson(Map<String, dynamic> value) {
    final List<IntegrityRiskReason> reasons = <IntegrityRiskReason>[];
    final Object? rawReasons = value['reasons'];
    if (rawReasons is List) {
      for (final Object? item in rawReasons) {
        if (item is Map) {
          reasons.add(
            IntegrityRiskReason.fromJson(Map<String, dynamic>.from(item)),
          );
        }
      }
    }
    return IntegrityDecision(
      reportId: value['report_id'] as String? ?? '',
      score: (value['score'] as num?)?.toInt() ?? 0,
      verdict: value['verdict'] as String? ?? 'unknown',
      hardBlock: value['hard_block'] as bool? ?? false,
      reasons: reasons,
      mode: value['mode'] as String? ?? 'observe',
      freshForSeconds: (value['fresh_for_seconds'] as num?)?.toInt() ?? 0,
      remoteAttestation: value['remote_attestation'] as String? ?? 'not_used',
      createdAt: value['created_at'] as String? ?? '',
    );
  }
}

class RiskPolicyReason {
  RiskPolicyReason({
    required this.code,
    required this.points,
    required this.message,
  });

  final String code;
  final int points;
  final String message;

  factory RiskPolicyReason.fromJson(Map<String, dynamic> value) {
    return RiskPolicyReason(
      code: value['code'] as String? ?? 'unknown',
      points: (value['points'] as num?)?.toInt() ?? 0,
      message: value['message'] as String? ?? '',
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'code': code,
        'points': points,
        'message': message,
      };
}

class RiskPolicyDecision {
  RiskPolicyDecision({
    required this.decisionId,
    required this.eventType,
    required this.mode,
    required this.score,
    required this.recommendedAction,
    required this.effectiveAction,
    required this.enforced,
    required this.reasons,
    required this.context,
    required this.thresholds,
    required this.createdAt,
  });

  final String decisionId;
  final String eventType;
  final String mode;
  final int score;
  final String recommendedAction;
  final String effectiveAction;
  final bool enforced;
  final List<RiskPolicyReason> reasons;
  final Map<String, dynamic> context;
  final Map<String, dynamic> thresholds;
  final String createdAt;

  factory RiskPolicyDecision.fromJson(Map<String, dynamic> value) {
    final List<RiskPolicyReason> parsedReasons = <RiskPolicyReason>[];
    final Object? rawReasons = value['reasons'];
    if (rawReasons is List) {
      for (final Object? item in rawReasons) {
        if (item is Map) {
          parsedReasons.add(
            RiskPolicyReason.fromJson(Map<String, dynamic>.from(item)),
          );
        }
      }
    }

    return RiskPolicyDecision(
      decisionId: value['decision_id'] as String? ?? 'not-persisted',
      eventType: value['event_type'] as String? ?? 'unknown',
      mode: value['mode'] as String? ?? 'observe',
      score: (value['score'] as num?)?.toInt() ?? 0,
      recommendedAction: value['recommended_action'] as String? ?? 'allow',
      effectiveAction: value['effective_action'] as String? ?? 'allow',
      enforced: value['enforced'] as bool? ?? false,
      reasons: parsedReasons,
      context: value['context'] is Map
          ? Map<String, dynamic>.from(value['context'] as Map)
          : <String, dynamic>{},
      thresholds: value['thresholds'] is Map
          ? Map<String, dynamic>.from(value['thresholds'] as Map)
          : <String, dynamic>{},
      createdAt: value['created_at'] as String? ?? '',
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'decision_id': decisionId,
        'event_type': eventType,
        'mode': mode,
        'score': score,
        'recommended_action': recommendedAction,
        'effective_action': effectiveAction,
        'enforced': enforced,
        'reasons': reasons.map((RiskPolicyReason r) => r.toJson()).toList(),
        'context': context,
        'thresholds': thresholds,
        'created_at': createdAt,
      };
}

class AccountSession {
  AccountSession({
    required this.accountId,
    required this.accessToken,
    required this.refreshToken,
    this.policy,
    this.scope = 'full',
    this.limitedCauses = const <String>[],
    this.upgradeRoutes = const <String>[],
    this.acceptedCauses = const <String>[],
    this.acceptedUntil,
  });

  final String accountId;
  final String accessToken;
  final String refreshToken;
  final RiskPolicyDecision? policy;

  /// `full` or `limited` (DESIGN.md 70). A limited session reaches only the
  /// upgrade endpoints, the integrity scan and the paths a DBA lists.
  final String scope;
  final List<String> limitedCauses;

  /// The upgrade routes the server says are open to this user right now;
  /// empty means none is, and the user should contact support.
  final List<String> upgradeRoutes;

  /// The soft causes an upgrade's proof accepted, kept until [acceptedUntil]
  /// (DESIGN.md 72).
  final List<String> acceptedCauses;
  final String? acceptedUntil;

  bool get isLimited => scope == 'limited';

  static List<String> _strings(Object? value) => value is List
      ? value.map((Object? item) => item.toString()).toList(growable: false)
      : const <String>[];

  factory AccountSession.fromApi(Map<String, dynamic> value) {
    return AccountSession(
      accountId: value['account_id'] as String,
      accessToken: value['access_token'] as String,
      refreshToken: value['refresh_token'] as String,
      policy: value['policy'] is Map
          ? RiskPolicyDecision.fromJson(
              Map<String, dynamic>.from(value['policy'] as Map),
            )
          : null,
      scope: value['scope'] as String? ?? 'full',
      limitedCauses: _strings(value['limited_causes']),
      upgradeRoutes: _strings(value['upgrade_routes']),
      acceptedCauses: _strings(value['accepted_causes']),
      acceptedUntil: value['accepted_until'] as String?,
    );
  }

  factory AccountSession.fromStoredJson(Map<String, dynamic> value) {
    return AccountSession.fromApi(value);
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'account_id': accountId,
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'policy': policy?.toJson(),
        'scope': scope,
        'limited_causes': limitedCauses,
        'upgrade_routes': upgradeRoutes,
        'accepted_causes': acceptedCauses,
        'accepted_until': acceptedUntil,
      };
}

class DeviceSummary {
  DeviceSummary({
    required this.installationId,
    required this.deviceId,
    required this.platform,
    required this.deviceStatus,
    required this.keyThumbprint,
    required this.keyAlgorithm,
    required this.method,
    required this.confidence,
    required this.installationCount,
    required this.linkedAccountCount,
    required this.createdAt,
    required this.lastSeenAt,
    required this.policy,
  });

  final String installationId;
  final String deviceId;
  final String platform;
  final String deviceStatus;
  final String keyThumbprint;
  final String keyAlgorithm;
  final String method;
  final String confidence;
  final int installationCount;
  final int linkedAccountCount;
  final String createdAt;
  final String lastSeenAt;
  final RiskPolicyDecision? policy;

  factory DeviceSummary.fromJson(Map<String, dynamic> value) {
    final Map<String, dynamic> recognition =
        Map<String, dynamic>.from(value['recognition'] as Map);
    return DeviceSummary(
      installationId: value['installation_id'] as String,
      deviceId: value['device_id'] as String,
      platform: value['platform'] as String,
      deviceStatus: value['device_status'] as String? ?? 'active',
      keyThumbprint: value['key_thumbprint'] as String,
      keyAlgorithm: value['key_algorithm'] as String? ?? 'unknown',
      method: recognition['method'] as String,
      confidence: recognition['confidence'] as String,
      installationCount:
          (value['installation_count'] as num?)?.toInt() ?? 0,
      linkedAccountCount:
          (value['linked_account_count'] as num?)?.toInt() ?? 0,
      createdAt: value['created_at'] as String,
      lastSeenAt: value['last_seen_at'] as String,
      policy: value['policy'] is Map
          ? RiskPolicyDecision.fromJson(
              Map<String, dynamic>.from(value['policy'] as Map),
            )
          : null,
    );
  }
}

class SecureIdentityStore {
  SecureIdentityStore({
    NativeInstallationKey? nativeKey,
    NativeStepUpKey? stepUpKey,
  })  : _nativeKey = nativeKey ?? NativeInstallationKey(),
        _stepUpKey = stepUpKey ?? NativeStepUpKey(),
        _storage = const FlutterSecureStorage();

  // The first prototype serialized an RSA private key under this name. It is
  // deleted during migration and is never parsed by this version.
  static const String _legacyIdentityKey = 'recognition.identity.v1';
  static const String _legacyRegistrationKey = 'recognition.registration.v1';
  static const String _legacyAccountSessionKey =
      'recognition.account_session.v1';

  static const String _installationIdKey =
      'recognition.installation_id.v2';
  static const String _registrationKey = 'recognition.registration.v2';
  static const String _accountSessionKey =
      'recognition.account_session.v2';

  static const IOSOptions _iosOptions = IOSOptions(
    accessibility: KeychainAccessibility.first_unlock_this_device,
    synchronizable: false,
  );

  final NativeInstallationKey _nativeKey;
  final NativeStepUpKey _stepUpKey;
  final FlutterSecureStorage _storage;

  /// Step-up is optional: failing to remove its key must never block the
  /// installation identity.
  Future<void> _deleteStepUpKeyQuietly() async {
    try {
      await _stepUpKey.deleteKey();
    } on NativeKeyException catch (error) {
      debugPrint('STEPUP: could not delete the step-up key: $error');
    }
  }

  Future<String?> _read(String key) {
    return _storage.read(key: key, iOptions: _iosOptions);
  }

  Future<void> _write(String key, String value) {
    return _storage.write(key: key, value: value, iOptions: _iosOptions);
  }

  Future<void> _delete(String key) {
    return _storage.delete(key: key, iOptions: _iosOptions);
  }

  Future<void> _migrateLegacyPrototypeIfNeeded() async {
    final String? legacyPrivateKey = await _read(_legacyIdentityKey);
    if (legacyPrivateKey != null && legacyPrivateKey.isNotEmpty) {
      // A partially completed migration may already have generated a native
      // key. Delete it so migration always starts with one coherent identity.
      await _nativeKey.deleteKey();
      await Future.wait(<Future<void>>[
        _delete(_legacyIdentityKey),
        _delete(_legacyRegistrationKey),
        _delete(_legacyAccountSessionKey),
        _delete(_installationIdKey),
        _delete(_registrationKey),
        _delete(_accountSessionKey),
      ]);
      return;
    }

    // These old records contain tokens and registration state bound to the
    // exportable RSA installation and cannot be reused with the native key.
    await Future.wait(<Future<void>>[
      _delete(_legacyRegistrationKey),
      _delete(_legacyAccountSessionKey),
    ]);
  }

  Future<InstallationIdentity> loadOrCreateIdentity() async {
    await _migrateLegacyPrototypeIfNeeded();

    String? installationId = await _read(_installationIdKey);
    final bool hadInstallationId =
        installationId != null && installationId.isNotEmpty;
    final NativeKeyMetadata metadata = await _nativeKey.getOrCreateKey();
    if (metadata.created) {
      // A new installation key is a new server installation, and a step-up
      // key binds only at first registration: rotate it so the new
      // installation enrols its own.
      await _deleteStepUpKeyQuietly();
    }

    if (!hadInstallationId) {
      installationId = Uuid().v4();
      await _write(_installationIdKey, installationId);
    } else if (metadata.created) {
      // The OS key disappeared while the UUID remained. Reusing that UUID with
      // a different public key would correctly trigger a server collision.
      // Treat this as a fresh installation and let the reinstall hint correlate
      // it back to the recognized device.
      installationId = Uuid().v4();
      await Future.wait(<Future<void>>[
        _write(_installationIdKey, installationId),
        _delete(_registrationKey),
        _delete(_accountSessionKey),
      ]);
    }

    return InstallationIdentity(
      installationId: installationId!,
      nativeKey: _nativeKey,
      metadata: metadata,
    );
  }

  Future<void> saveIdentity(InstallationIdentity identity) {
    // Only the opaque UUID is stored by Dart. The private key never crosses the
    // platform channel and is never serialized into Flutter storage.
    return _write(_installationIdKey, identity.installationId);
  }

  Future<RegistrationState?> loadRegistration() async {
    final String? stored = await _read(_registrationKey);
    if (stored == null || stored.isEmpty) {
      return null;
    }
    return RegistrationState.fromStoredJson(
      Map<String, dynamic>.from(jsonDecode(stored) as Map),
    );
  }

  Future<void> saveRegistration(RegistrationState state) {
    return _write(_registrationKey, jsonEncode(state.toJson()));
  }

  Future<AccountSession?> loadAccountSession() async {
    final String? stored = await _read(_accountSessionKey);
    if (stored == null || stored.isEmpty) {
      return null;
    }
    return AccountSession.fromStoredJson(
      Map<String, dynamic>.from(jsonDecode(stored) as Map),
    );
  }

  Future<void> saveAccountSession(AccountSession session) {
    return _write(_accountSessionKey, jsonEncode(session.toJson()));
  }

  Future<void> clearAccountSession() {
    return _delete(_accountSessionKey);
  }

  Future<void> clearLocalInstallation() async {
    await _nativeKey.deleteKey();
    await _deleteStepUpKeyQuietly();
    await Future.wait(<Future<void>>[
      _delete(_legacyIdentityKey),
      _delete(_legacyRegistrationKey),
      _delete(_legacyAccountSessionKey),
      _delete(_installationIdKey),
      _delete(_registrationKey),
      _delete(_accountSessionKey),
    ]);
  }
}

class ReinstallHint {
  const ReinstallHint({required this.kind, required this.value});

  final String kind;
  final String value;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'kind': kind,
        'value': value,
      };
}

class ReinstallHintReader {
  static const AndroidId _androidId = AndroidId();
  final DeviceInfoPlugin _deviceInfo = DeviceInfoPlugin();

  Future<ReinstallHint?> read() async {
    if (kIsWeb) {
      return null;
    }
    try {
      if (Platform.isAndroid) {
        final String? value = await _androidId.getId();
        if (value != null && value.trim().isNotEmpty) {
          final String digest = crypto.sha256
              .convert(utf8.encode(
                'device-recognition-hint-v1|android_id|${value.trim().toLowerCase()}',
              ))
              .toString();
          return ReinstallHint(kind: 'android_id_sha256', value: digest);
        }
      } else if (Platform.isIOS) {
        final IosDeviceInfo info = await _deviceInfo.iosInfo;
        final String? value = info.identifierForVendor;
        if (value != null && value.trim().isNotEmpty) {
          final String digest = crypto.sha256
              .convert(utf8.encode(
                'device-recognition-hint-v1|idfv|${value.trim().toLowerCase()}',
              ))
              .toString();
          return ReinstallHint(kind: 'idfv_sha256', value: digest);
        }
      }
    } catch (_) {
      // A missing hint must never stop cryptographic installation identity.
    }
    return null;
  }
}


class AccessProofFixture {
  const AccessProofFixture({
    required this.bearerToken,
    required this.signedMethod,
    required this.signedPath,
    required this.encodedBody,
    required this.proofPayload,
    required this.signature,
    required this.timestamp,
    required this.nonce,
  });

  final String bearerToken;
  final String signedMethod;
  final String signedPath;
  final String encodedBody;
  final String proofPayload;
  final String signature;
  final int timestamp;
  final String nonce;
}

class DeviceApi {
  DeviceApi({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;

  String get _base {
    if (apiBaseUrl.isEmpty) {
      throw ApiException(
        'No API_BASE_URL was provided at build time. Rebuild with '
        '--dart-define=API_BASE_URL=https://<host>',
        code: 'api_base_url_missing',
      );
    }
    // A release build talks HTTPS only (review F8, DESIGN.md 63). The Android
    // manifest refuses cleartext in release too; this makes a mistyped
    // endpoint fail loudly instead of sending tokens in the clear.
    if (kReleaseMode && !apiBaseUrl.toLowerCase().startsWith('https://')) {
      throw ApiException(
        'API_BASE_URL must be an https:// URL in a release build.',
        code: 'api_base_url_insecure',
      );
    }
    return apiBaseUrl.endsWith('/')
        ? apiBaseUrl.substring(0, apiBaseUrl.length - 1)
        : apiBaseUrl;
  }

  Future<Map<String, dynamic>> _request(
    String method,
    String path, {
    Map<String, dynamic>? body,
    String? bearerToken,
    Map<String, String>? extraHeaders,
    String? encodedBody,
  }) async {
    final Uri uri = Uri.parse('$_base$path');
    final Map<String, String> headers = <String, String>{
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      if (bearerToken != null) 'Authorization': 'Bearer $bearerToken',
      if (extraHeaders != null) ...extraHeaders,
    };

    late final http.Response response;
    try {
      if (method == 'GET') {
        response = await _client
            .get(uri, headers: headers)
            .timeout(_networkTimeout);
      } else {
        final String requestBody =
            encodedBody ?? jsonEncode(body ?? <String, dynamic>{});
        response = await _client
            .post(
              uri,
              headers: headers,
              body: requestBody,
            )
            .timeout(_networkTimeout);
      }
    } on TimeoutException {
      throw ApiException('The server did not respond before the timeout.');
    } on SocketException catch (error) {
      throw ApiException('Network connection failed: ${error.message}');
    } on http.ClientException catch (error) {
      throw ApiException('HTTP connection failed: ${error.message}');
    }

    Map<String, dynamic> decoded = <String, dynamic>{};
    if (response.body.trim().isNotEmpty) {
      try {
        decoded = Map<String, dynamic>.from(
          jsonDecode(response.body) as Map,
        );
      } catch (_) {
        throw ApiException(
          'The server returned a non-JSON response.',
          statusCode: response.statusCode,
        );
      }
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final Map<String, dynamic>? error = decoded['error'] is Map
          ? Map<String, dynamic>.from(decoded['error'] as Map)
          : null;
      throw ApiException(
        error?['message'] as String? ??
            'The server rejected the request (${response.statusCode}).',
        statusCode: response.statusCode,
        code: error?['code'] as String?,
        details: error?['details'] is Map
            ? Map<String, dynamic>.from(error?['details'] as Map)
            : null,
      );
    }
    return decoded;
  }

  String _b64UrlNoPadding(List<int> value) {
    return base64Url.encode(value).replaceAll('=', '');
  }

  List<int> _freshNonce() {
    final math.Random random = math.Random.secure();
    return List<int>.generate(32, (_) => random.nextInt(256));
  }

  Future<AccessProofFixture> buildAccessProofFixture(
    String method,
    String path, {
    Map<String, dynamic>? body,
    required String bearerToken,
    required InstallationIdentity signingIdentity,
    String? proofInstallationId,
    int? timestampSeconds,
    List<int>? nonceBytes,
  }) async {
    final String normalizedMethod = method.toUpperCase();
    final String encodedBody = normalizedMethod == 'GET'
        ? ''
        : jsonEncode(body ?? <String, dynamic>{});
    final String bodyHash =
        crypto.sha256.convert(utf8.encode(encodedBody)).toString();
    final String tokenHash =
        crypto.sha256.convert(utf8.encode(bearerToken)).toString();
    final List<int> actualNonce = nonceBytes ?? _freshNonce();
    final String nonce = _b64UrlNoPadding(actualNonce);
    final int timestamp = timestampSeconds ??
        DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;

    // Access proof v2 (DESIGN.md 63): the query string is signed too, exactly
    // as sent; v1 left it outside the signature.
    final Uri target = Uri.parse(path);
    final Map<String, dynamic> proof = <String, dynamic>{
      'access_token_sha256': tokenHash,
      'body_sha256': bodyHash,
      'installation_id': proofInstallationId ?? signingIdentity.installationId,
      'method': normalizedMethod,
      'nonce': nonce,
      'path': target.path,
      'query': target.query,
      'timestamp': timestamp,
      'version': 2,
    };

    // The native private key signs the exact JSON bytes represented by this
    // base64url value. The private key never leaves Android Keystore/iOS.
    final String proofPayload =
        _b64UrlNoPadding(utf8.encode(jsonEncode(proof)));
    final String signature = await signingIdentity.signPayload(proofPayload);

    return AccessProofFixture(
      bearerToken: bearerToken,
      signedMethod: normalizedMethod,
      signedPath: path,
      encodedBody: encodedBody,
      proofPayload: proofPayload,
      signature: signature,
      timestamp: timestamp,
      nonce: nonce,
    );
  }

  Future<Map<String, dynamic>> sendAccessProofFixture(
    AccessProofFixture fixture, {
    String? actualMethod,
    String? actualPath,
    String? actualEncodedBody,
  }) {
    final String method = (actualMethod ?? fixture.signedMethod).toUpperCase();
    final String path = actualPath ?? fixture.signedPath;

    return _request(
      method,
      path,
      bearerToken: fixture.bearerToken,
      encodedBody: method == 'GET'
          ? null
          : (actualEncodedBody ?? fixture.encodedBody),
      extraHeaders: <String, String>{
        'X-Access-Proof': fixture.proofPayload,
        'X-Access-Signature': fixture.signature,
      },
    );
  }

  Future<Map<String, dynamic>> _protectedRequest(
    String method,
    String path, {
    Map<String, dynamic>? body,
    required String bearerToken,
    required InstallationIdentity signingIdentity,
    String? proofInstallationId,
  }) async {
    final AccessProofFixture fixture = await buildAccessProofFixture(
      method,
      path,
      body: body,
      bearerToken: bearerToken,
      signingIdentity: signingIdentity,
      proofInstallationId: proofInstallationId,
    );
    return sendAccessProofFixture(fixture);
  }

  Future<RegistrationState> registerInstallation(
    InstallationIdentity identity,
    ReinstallHint? hint, {
    StepUpKeyMetadata? stepUpKey,
  }) async {
    final Map<String, dynamic> response = await _request(
      'POST',
      '/v1/installations/register',
      body: <String, dynamic>{
        'installation_id': identity.installationId,
        'platform': Platform.isAndroid ? 'android' : 'ios',
        'public_key': identity.publicKeyJson,
        'reinstall_hint': hint?.toJson(),
        // What the platform keystore reports about how this key is protected.
        // The server stores it so a Secure Enclave / StrongBox key is
        // distinguishable from a software fallback, which it previously was
        // not: the client has always read these values and never sent them.
        //
        // This is a client claim, not proof - a compromised client can lie.
        // Its value is comparative: the key thumbprint is the authoritative
        // identity, and a non-exportable hardware key cannot move into
        // software, so the same key later claiming a weaker level is a
        // contradiction the server can act on.
        'key_security': <String, dynamic>{
          'security_level': identity.securityLevel,
          'hardware_backed': identity.hardwareBacked,
          'provider': identity.provider,
        },
        // The optional step-up key and how the keystore protects it. The server
        // binds it only when this installation key is new, and records the
        // factor/mode/window so a weaker-than-policy key is visible.
        if (stepUpKey != null) 'stepup_public_key': stepUpKey.publicKey,
        if (stepUpKey != null) 'stepup_key_auth': stepUpKey.authJson,
      },
    );
    return RegistrationState.fromJson(response);
  }

  Future<Map<String, dynamic>> createInstallationChallenge(
    String installationId,
  ) {
    return _request(
      'POST',
      '/v1/installations/challenge',
      body: <String, dynamic>{'installation_id': installationId},
    );
  }

  Future<Map<String, dynamic>> verifyInstallation({
    required String installationId,
    required String challengeId,
    required String payload,
    required String signature,
  }) {
    return _request(
      'POST',
      '/v1/installations/verify',
      body: <String, dynamic>{
        'installation_id': installationId,
        'challenge_id': challengeId,
        'payload': payload,
        'signature': signature,
      },
    );
  }

  Future<DeviceSummary> deviceSummary(
    String token,
    InstallationIdentity identity,
  ) async {
    final Map<String, dynamic> value = await _protectedRequest(
      'GET',
      '/v1/device/me',
      bearerToken: token,
      signingIdentity: identity,
    );
    return DeviceSummary.fromJson(value);
  }

  Future<Map<String, dynamic>> integrityChallenge({
    required String deviceToken,
    required InstallationIdentity signingIdentity,
  }) {
    return _protectedRequest(
      'POST',
      '/v1/integrity/challenge',
      bearerToken: deviceToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{},
    );
  }

  Future<IntegrityDecision> submitIntegrityReport({
    required String deviceToken,
    required InstallationIdentity signingIdentity,
    required String reportPayload,
    required String reportSignature,
  }) async {
    final Map<String, dynamic> value = await _protectedRequest(
      'POST',
      '/v1/integrity/report',
      bearerToken: deviceToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{
        'report_payload': reportPayload,
        'report_signature': reportSignature,
      },
    );
    if (value['integrity'] is! Map) {
      throw ApiException(
        'The server returned no integrity decision.',
        code: 'missing_integrity_decision',
      );
    }
    return IntegrityDecision.fromJson(
      Map<String, dynamic>.from(value['integrity'] as Map),
    );
  }

  Future<AccountSession> registerAccount({
    required String deviceToken,
    required InstallationIdentity signingIdentity,
    required String handle,
    required String password,
  }) async {
    final Map<String, dynamic> value = await _protectedRequest(
      'POST',
      '/v1/accounts/register',
      bearerToken: deviceToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{
        'handle': handle,
        'password': password,
      },
    );
    return AccountSession.fromApi(value);
  }

  Future<AccountSession> loginAccount({
    required String deviceToken,
    required InstallationIdentity signingIdentity,
    required String handle,
    required String password,
  }) async {
    final Map<String, dynamic> value = await _protectedRequest(
      'POST',
      '/v1/accounts/login',
      bearerToken: deviceToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{
        'handle': handle,
        'password': password,
      },
    );
    return AccountSession.fromApi(value);
  }

  /// The DBA's step-up policy, readable before sign-in (DESIGN.md 79).
  Future<StepUpPolicy> stepUpPolicy() async {
    return StepUpPolicy.fromServer(
      await _request('GET', '/v1/policy/step-up'),
    );
  }

  Future<Map<String, dynamic>> accountMe({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    String? proofInstallationId,
  }) {
    return _protectedRequest(
      'GET',
      '/v1/account/me',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      proofInstallationId: proofInstallationId,
    );
  }

  Future<Map<String, dynamic>> protectedEcho({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required Map<String, dynamic> body,
  }) {
    return _protectedRequest(
      'POST',
      '/v1/account/protected-echo',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      body: body,
    );
  }

  /// The demo crown-jewel endpoint. With [signStepUp], the request is frozen
  /// first -- token, method, path, query, body digest and nonce -- and the
  /// step-up key signs exactly that request (proof v2, DESIGN.md 63), so an
  /// approval cannot be attached to any other request. [signStepUp] runs BEFORE
  /// the access proof is signed: the user may take a while at the prompt, and
  /// the access proof's timestamp window should start after that.
  Future<Map<String, dynamic>> sensitiveEcho({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required Map<String, dynamic> body,
    String? stepUpFactor,
    Future<String> Function(String payload)? signStepUp,
    String? appPin,
  }) {
    return _postWithStepUp(
      path: '/v1/account/sensitive-echo',
      accessToken: accessToken,
      signingIdentity: signingIdentity,
      body: body,
      stepUpFactor: stepUpFactor,
      signStepUp: signStepUp,
      appPin: appPin,
    );
  }

  /// A protected POST that may also carry a step-up proof v2 over exactly
  /// this request -- the sensitive path, a session upgrade, or approving
  /// another phone's upgrade -- and the app PIN the server checks
  /// (DESIGN.md 78), as the DBA's stepup_method asks.
  Future<Map<String, dynamic>> _postWithStepUp({
    required String path,
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required Map<String, dynamic> body,
    String? stepUpFactor,
    Future<String> Function(String payload)? signStepUp,
    String? appPin,
  }) async {
    final List<int> nonceBytes = _freshNonce();
    final String encodedBody = jsonEncode(body);
    final Map<String, String> stepUp = <String, String>{};
    if (signStepUp != null) {
      final String payload = _b64UrlNoPadding(utf8.encode(jsonEncode(
        <String, dynamic>{
          'version': 2,
          'purpose': 'stepup',
          'installation_id': signingIdentity.installationId,
          'access_token_sha256':
              crypto.sha256.convert(utf8.encode(accessToken)).toString(),
          'method': 'POST',
          'path': path,
          'query': '',
          'body_sha256':
              crypto.sha256.convert(utf8.encode(encodedBody)).toString(),
          'factor': stepUpFactor,
          'nonce': _b64UrlNoPadding(nonceBytes),
          'timestamp': DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
        },
      )));
      stepUp['X-Step-Up-Proof'] = payload;
      stepUp['X-Step-Up-Signature'] = await signStepUp(payload);
    }
    final AccessProofFixture fixture = await buildAccessProofFixture(
      'POST',
      path,
      body: body,
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      nonceBytes: nonceBytes,
    );
    if (fixture.encodedBody != encodedBody) {
      // The step-up approval covers these exact bytes; sending others would
      // be refused as stepup_binding_mismatch, so fail here instead.
      throw ApiException(
        'The request body changed after it was approved.',
        code: 'stepup_body_changed',
      );
    }
    return _request(
      'POST',
      fixture.signedPath,
      bearerToken: fixture.bearerToken,
      encodedBody: fixture.encodedBody,
      extraHeaders: <String, String>{
        'X-Access-Proof': fixture.proofPayload,
        'X-Access-Signature': fixture.signature,
        ...stepUp,
        if (appPin != null && appPin.isNotEmpty) 'X-App-PIN': appPin,
      },
    );
  }

  /// Sets or replaces this account's app PIN (DESIGN.md 78): a full session
  /// and the account password; the server keeps only a verifier.
  Future<Map<String, dynamic>> setAppPin({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required String password,
    required String pin,
  }) {
    return _protectedRequest(
      'POST',
      '/v1/account/app-pin',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{'password': password, 'pin': pin},
    );
  }

  /// Re-enrols this installation's step-up key (DESIGN.md 58): the account
  /// password plus a proof signed by the new step-up key over this request's
  /// access-proof nonce. [signKeyProof] receives the nonce and returns the
  /// proof fields; like the sensitive-op step-up, it runs before the access
  /// proof is signed so time at the prompt does not eat its timestamp window.
  Future<Map<String, dynamic>> reenrolStepUpKey({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required String password,
    required StepUpKeyMetadata stepUpKey,
    required Future<Map<String, String>> Function(String nonce) signKeyProof,
  }) async {
    final List<int> nonceBytes = _freshNonce();
    final Map<String, String> keyProof =
        await signKeyProof(_b64UrlNoPadding(nonceBytes));
    final AccessProofFixture fixture = await buildAccessProofFixture(
      'POST',
      '/v1/installations/stepup-key',
      body: <String, dynamic>{
        'password': password,
        'stepup_public_key': stepUpKey.publicKey,
        'stepup_key_auth': stepUpKey.authJson,
        ...keyProof,
      },
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      nonceBytes: nonceBytes,
    );
    return sendAccessProofFixture(fixture);
  }

  Future<RiskPolicyDecision> currentPolicy({
    required String accessToken,
    required InstallationIdentity signingIdentity,
  }) async {
    final Map<String, dynamic> value = await _protectedRequest(
      'GET',
      '/v1/policy/me',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
    );
    if (value['policy'] is! Map) {
      throw ApiException(
        'The server returned no policy decision.',
        code: 'missing_policy_decision',
      );
    }
    return RiskPolicyDecision.fromJson(
      Map<String, dynamic>.from(value['policy'] as Map),
    );
  }

  /// Upgrades a limited session to a full one (DESIGN.md 70, 72). [route] is
  /// `recheck` (no proof: works once no soft cause remains), `stepup` (needs
  /// [signStepUp]) or `approval` (needs the [requestId] another phone approved).
  Future<AccountSession> upgradeSession({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required String route,
    String? requestId,
    String? stepUpFactor,
    Future<String> Function(String payload)? signStepUp,
    String? appPin,
  }) async {
    final Map<String, dynamic> value = await _postWithStepUp(
      path: '/v1/auth/upgrade',
      accessToken: accessToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{
        'route': route,
        'request_id': ?requestId,
      },
      stepUpFactor: stepUpFactor,
      signStepUp: signStepUp,
      appPin: appPin,
    );
    return AccountSession.fromApi(value);
  }

  /// Starts an upgrade another party must confirm: `approval` (route 2).
  Future<Map<String, dynamic>> requestUpgrade({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required String route,
  }) {
    return _protectedRequest(
      'POST',
      '/v1/auth/upgrade/request',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{'route': route},
    );
  }

  /// Pending approval requests from this account's OTHER installations.
  Future<List<Map<String, dynamic>>> pendingApprovals({
    required String accessToken,
    required InstallationIdentity signingIdentity,
  }) async {
    final Map<String, dynamic> value = await _protectedRequest(
      'GET',
      '/v1/auth/approvals',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
    );
    final Object? approvals = value['approvals'];
    return approvals is List
        ? approvals
            .whereType<Map>()
            .map((Map item) => Map<String, dynamic>.from(item))
            .toList(growable: false)
        : <Map<String, dynamic>>[];
  }

  /// Approves another installation's upgrade; the server requires a step-up
  /// over this very request -- the screen-lock key's proof, the app PIN, or
  /// both, as the DBA's stepup_method says (DESIGN.md 78).
  Future<Map<String, dynamic>> approveUpgrade({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required String requestId,
    required String? stepUpFactor,
    Future<String> Function(String payload)? signStepUp,
    String? appPin,
  }) {
    return _postWithStepUp(
      path: '/v1/auth/approvals/$requestId/approve',
      accessToken: accessToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{},
      stepUpFactor: stepUpFactor,
      signStepUp: signStepUp,
      appPin: appPin,
    );
  }

  Future<Map<String, dynamic>> denyUpgrade({
    required String accessToken,
    required InstallationIdentity signingIdentity,
    required String requestId,
  }) {
    return _protectedRequest(
      'POST',
      '/v1/auth/approvals/$requestId/deny',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{},
    );
  }

  /// Signs the session's refresh family out on the server (DESIGN.md 76): its
  /// refresh token and every access token of the family stop working at once.
  Future<Map<String, dynamic>> logout({
    required String accessToken,
    required InstallationIdentity signingIdentity,
  }) {
    return _protectedRequest(
      'POST',
      '/v1/auth/logout',
      bearerToken: accessToken,
      signingIdentity: signingIdentity,
      body: <String, dynamic>{},
    );
  }

  Future<Map<String, dynamic>> refreshChallenge(String refreshToken) {
    return _request(
      'POST',
      '/v1/auth/refresh/challenge',
      bearerToken: refreshToken,
    );
  }

  Future<AccountSession> refreshAccount({
    required String refreshToken,
    required String challengeId,
    required String payload,
    required String signature,
  }) async {
    final Map<String, dynamic> value = await _request(
      'POST',
      '/v1/auth/refresh',
      bearerToken: refreshToken,
      body: <String, dynamic>{
        'challenge_id': challengeId,
        'payload': payload,
        'signature': signature,
      },
    );
    return AccountSession.fromApi(value);
  }

  void close() => _client.close();
}

class DeviceRecognitionController extends ChangeNotifier {
  DeviceRecognitionController({
    SecureIdentityStore? store,
    ReinstallHintReader? hintReader,
    DeviceApi? api,
    NativeIntegrityCollector? integrityCollector,
    NativeStepUpKey? stepUpKeyProvider,
  })  : _store = store ?? SecureIdentityStore(),
        _hintReader = hintReader ?? ReinstallHintReader(),
        _api = api ?? DeviceApi(),
        _integrityCollector = integrityCollector ?? NativeIntegrityCollector(),
        _stepUpKeyProvider = stepUpKeyProvider ?? NativeStepUpKey();

  final SecureIdentityStore _store;
  final ReinstallHintReader _hintReader;
  final DeviceApi _api;
  final NativeIntegrityCollector _integrityCollector;
  final NativeStepUpKey _stepUpKeyProvider;

  InstallationIdentity? identity;
  RegistrationState? registration;
  DeviceSummary? summary;
  AccountSession? accountSession;
  ReinstallHint? reinstallHint;
  String? deviceToken;
  String? lastError;
  String? boundRefreshTestResult;
  String? stolenRefreshTestResult;
  String? boundAccessTestResult;
  String? stolenAccessTestResult;
  String? replayAttackTestResult;
  String? bodyTamperTestResult;
  String? pathMethodTamperTestResult;
  String? timestampExpiryTestResult;
  RiskPolicyDecision? latestPolicy;
  IntegrityDecision? latestIntegrity;
  List<String> lastIntegrityProbes = <String>[];
  String? lastIntegrityTestFixture;
  String? integrityAttackTestResult;
  StepUpKeyMetadata? stepUpKey;
  String? stepUpUnavailable;
  String? stepUpTestResult;

  /// The step-up policy the key was last prepared for (DESIGN.md 79).
  StepUpPolicy? stepUpPolicy;

  /// This phone's bound key was made for another factor than the server's
  /// policy now names, so every step-up with it would be refused
  /// (stepup_factor_mismatch) until the user re-enrols with the password.
  String? stepUpPolicyMismatch;
  String? limitedSessionResult;
  String? pendingUpgradeRequestId;
  List<Map<String, dynamic>> approvalRequests = <Map<String, dynamic>>[];

  /// What approving a request accepts, as the server worded it: one line per
  /// reason (DESIGN.md 76). An approval covers exactly these; anything found
  /// later needs a new decision.
  List<String> approvalReasonLines(Map<String, dynamic> request) {
    final Object? reasons = request['reasons'];
    if (reasons is! List) {
      return <String>[];
    }
    return <String>[
      for (final Object? reason in reasons)
        if (reason is Map)
          '- ${reason['message'] ?? reason['code']} (+${reason['points']})',
    ];
  }

  /// The requests still open by their own expiry. The server leaves out lapsed
  /// and replaced requests (DESIGN.md 75); this hides one that lapsed since the
  /// list was loaded. Found on the Vivo, 2026-10-13: a lapsed request stayed on
  /// screen, and approving it asked for the PIN only to get a 404.
  List<Map<String, dynamic>> get openApprovalRequests {
    final DateTime now = DateTime.now().toUtc();
    return approvalRequests.where((Map<String, dynamic> request) {
      final DateTime? expires =
          DateTime.tryParse(request['expires_at'] as String? ?? '');
      return expires == null || expires.isAfter(now);
    }).toList(growable: false);
  }
  String status = 'Not started';
  bool busy = false;

  Future<void> _run(
    String startingStatus,
    Future<void> Function() operation,
  ) async {
    if (busy) {
      return;
    }
    busy = true;
    lastError = null;
    status = startingStatus;
    notifyListeners();
    try {
      await operation();
    } on NativeKeyException catch (error) {
      lastError = '${error.message} [${error.code}]';
      status = 'Operation failed';
    } on ApiException catch (error) {
      final Object? rawPolicy = error.details?['policy'];
      if (rawPolicy is Map) {
        latestPolicy = RiskPolicyDecision.fromJson(
          Map<String, dynamic>.from(rawPolicy),
        );
      }
      final Object? rawIntegrity = error.details?['integrity'];
      if (rawIntegrity is Map && rawIntegrity['report_id'] != null) {
        latestIntegrity = IntegrityDecision.fromJson(
          Map<String, dynamic>.from(rawIntegrity),
        );
      }
      lastError = error.code == null
          ? error.message
          : '${error.message} [${error.code}]';
      status = 'Operation failed';
    } on FormatException catch (error) {
      lastError = 'Local identity data is invalid: ${error.message}';
      status = 'Operation failed';
    } catch (error) {
      lastError = 'Unexpected error: $error';
      status = 'Operation failed';
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  Future<void> bootstrap() {
    return _run('Preparing the installation identity…', () async {
      identity = await _store.loadOrCreateIdentity();
      registration = await _store.loadRegistration();
      accountSession = await _store.loadAccountSession();
      // Nothing from a saved session is shown until the server confirms it
      // (_checkSavedSession): its risk decision may come from another server.
      latestPolicy = null;
      reinstallHint = await _hintReader.read();
      await _registerAndProve();
      await _checkSavedSession();
      status = 'Installation identity verified';
    });
  }

  /// A saved session is confirmed with the server at start, by one bound
  /// refresh, before anything from it is shown. A server that does not know
  /// it -- expired, revoked, or another database -- answers 401, and the
  /// session and its old risk decision are discarded. Any other failure keeps
  /// it: a network blip must not sign the user out. Found on the Huawei,
  /// 2026-10-12: after a switch to another database the app showed the old
  /// server's decision (four accounts on the phone) as current. Costs one
  /// refresh and one risk evaluation per start (DESIGN.md 75).
  Future<void> _checkSavedSession() async {
    final InstallationIdentity? currentIdentity = identity;
    if (accountSession == null || currentIdentity == null) {
      return;
    }
    try {
      // _registerAndProve has just scanned, as a refresh requires.
      await _rotateSession(currentIdentity);
      _logSession('start');
    } on ApiException catch (error) {
      if (error.statusCode != 401) {
        debugPrint('SESSION: start: saved session not checked: ${error.code}');
        return;
      }
      await _store.clearAccountSession();
      accountSession = null;
      latestPolicy = summary?.policy;
      debugPrint(
        'SESSION: start: the server does not know the saved session '
        '(${error.code}); discarded',
      );
    } catch (error) {
      debugPrint('SESSION: start: saved session not checked: $error');
    }
  }

  Future<void> reauthenticate() {
    return _run('Re-registering and proving key possession…', () async {
      identity ??= await _store.loadOrCreateIdentity();
      reinstallHint ??= await _hintReader.read();
      await _registerAndProve();
      status = 'Fresh device proof accepted';
    });
  }

  Future<StepUpPolicy> _readStepUpPolicy() async {
    try {
      final StepUpPolicy policy = await _api.stepUpPolicy();
      debugPrint('STEPUP: server policy ${policy.description}');
      return policy;
    } on ApiException catch (error) {
      debugPrint('STEPUP: policy unavailable (${error.code ?? error.message}); '
          'using the build values');
    } on FormatException catch (error) {
      debugPrint('STEPUP: ${error.message} Using the build values.');
    }
    return StepUpPolicy.buildFallback;
  }

  /// Prepares the screen-lock key as the server's policy says (DESIGN.md 79).
  /// An existing key that does not satisfy it is replaced while the server
  /// holds no key for this installation, or when [replaceMismatched] (a
  /// re-enrolment, which binds the new key). A bound key is never replaced
  /// silently: the server would refuse the new one until a re-enrolment, so
  /// a factor the policy no longer names is reported instead.
  Future<void> _prepareStepUpKey({bool replaceMismatched = false}) async {
    stepUpKey = null;
    stepUpUnavailable = null;
    stepUpPolicyMismatch = null;
    if (!stepUpEnabled) {
      stepUpUnavailable = 'disabled in this build (STEPUP_ENABLED=false)';
      return;
    }
    final StepUpPolicy policy = await _readStepUpPolicy();
    stepUpPolicy = policy;
    _stepUpKeyProvider.configuredMode = policy.mode;
    try {
      StepUpKeyMetadata key = await _stepUpKeyProvider.getOrCreateKey(
        factor: policy.factor,
        mode: policy.mode,
        windowSeconds: policy.windowSeconds,
      );
      if (!key.created && !policy.accepts(key)) {
        final RegistrationState? current = registration;
        final bool bound = current != null &&
            current.stepupKeyRegistered &&
            current.stepupKeyMatches != false;
        if (replaceMismatched || !bound) {
          debugPrint('STEPUP: replacing a ${key.description} key for the '
              'policy ${policy.description}');
          await _stepUpKeyProvider.deleteKey();
          key = await _stepUpKeyProvider.getOrCreateKey(
            factor: policy.factor,
            mode: policy.mode,
            windowSeconds: policy.windowSeconds,
          );
        } else if (key.factor != policy.factor && policy.usesScreenLock) {
          stepUpPolicyMismatch =
              'this key is ${key.factor}; the server now requires ${policy.factor}';
        }
      }
      stepUpKey = key;
      debugPrint(
        'STEPUP: key ${key.description}, ${key.securityLevel}, '
        'created=${key.created}',
      );
    } on NativeKeyException catch (error) {
      // Optional by design: no passcode, no biometric or an old OS must never
      // stop the installation from enrolling. The server then refuses
      // sensitive operations with stepup_key_not_registered.
      stepUpUnavailable = '${error.message} [${error.code}]';
      debugPrint('STEPUP: key unavailable: $stepUpUnavailable');
    } on FormatException catch (error) {
      stepUpUnavailable = error.message;
      debugPrint('STEPUP: key unavailable: $stepUpUnavailable');
    }
  }

  /// Thumbprint of the local step-up key the server last confirmed as bound:
  /// offered at registration and either bound there (new installation) or
  /// reported as matching. A key made afterwards -- found on the iPhone,
  /// 2026-10-04: a re-enrolment refused for a wrong password left a fresh,
  /// unbound key behind -- is not confirmed, so it is never offered for
  /// step-up; the server would refuse it with stepup_signature_invalid.
  String? _boundStepUpThumbprint;

  /// A local step-up key the server will actually accept: the one it last
  /// confirmed as bound to this installation.
  bool get stepUpUsable {
    final StepUpKeyMetadata? key = stepUpKey;
    return key != null &&
        key.thumbprint == _boundStepUpThumbprint &&
        !_stepUpKeyOtherAccount &&
        stepUpPolicyMismatch == null;
  }

  /// The server answered stepup_key_other_account: this phone's step-up key
  /// was re-enrolled by another account on it (DESIGN.md 58), so it cannot
  /// approve for the account signed in now. Found on the Huawei, 2026-10-12.
  /// Cleared by a re-enrolment, or when another account signs in.
  bool _stepUpKeyOtherAccount = false;

  void _noteStepUpRefusal(ApiException error) {
    if (error.code == 'stepup_key_other_account') {
      _stepUpKeyOtherAccount = true;
    }
  }

  /// Recovery when this installation's step-up key is lost or replaced
  /// (DESIGN.md 58): the user re-enters the account password and passes the
  /// new screen lock, which signs a proof with a fresh step-up key.
  Future<void> reenrolStepUpKey(String password) {
    stepUpTestResult = null;
    return _run('Re-enrolling the step-up key…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Log in first: re-enrolment needs the account.');
      }
      if (stepUpKey == null || stepUpPolicyMismatch != null) {
        await _prepareStepUpKey(replaceMismatched: true);
      }
      final StepUpKeyMetadata? key = stepUpKey;
      if (key == null) {
        throw ApiException(
          'No step-up key can be created: ${stepUpUnavailable ?? 'unknown'}',
        );
      }
      try {
        final Map<String, dynamic> value = await _api.reenrolStepUpKey(
          accessToken: session.accessToken,
          signingIdentity: currentIdentity,
          password: password,
          stepUpKey: key,
          signKeyProof: (String nonce) async {
            final String payload = _base64UrlNoPadding(
              utf8.encode(jsonEncode(<String, dynamic>{
                'version': 1,
                'purpose': 'stepup_reenrol',
                'installation_id': currentIdentity.installationId,
                'stepup_key_thumbprint': key.thumbprint,
                'nonce': nonce,
                'timestamp':
                    DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
              })),
            );
            final String signature = await _stepUpKeyProvider.sign(
              payload,
              reason: 'Confirm your new step-up key',
            );
            return <String, String>{
              'stepup_key_proof': payload,
              'stepup_key_signature': signature,
            };
          },
        );
        // Re-register so the server's view (bound, matching) is what shows.
        _stepUpKeyOtherAccount = false;
        await _registerAndProve();
        _recordStepUp(<String>[
          'PASS: step-up key re-enrolled',
          'POST /v1/installations/stepup-key: 200',
          'Key: ${key.description} (${key.securityLevel})',
          'Server now: registered=${registration?.stepupKeyRegistered} '
              'matches=${registration?.stepupKeyMatches}',
          'Policy downgrade: ${value['stepup_policy_downgrade']}',
        ]);
      } on NativeKeyException catch (error) {
        if (error.code == 'STEPUP_KEY_INVALIDATED') {
          stepUpKey = null;
          stepUpUnavailable = '${error.message} [${error.code}]';
        }
        _recordStepUp(<String>[
          'FAIL: the new step-up key could not sign',
          '${error.message} [${error.code}]',
        ]);
      } on ApiException catch (error) {
        _recordStepUp(<String>[
          'FAIL: re-enrolment refused',
          'POST /v1/installations/stepup-key: ${error.statusCode} ${error.code}',
        ]);
      }
    });
  }

  String get stepUpStatusLine {
    final StepUpKeyMetadata? key = stepUpKey;
    if (key == null) {
      return 'Step-up key: unavailable - ${stepUpUnavailable ?? 'not prepared yet'}';
    }
    final RegistrationState? current = registration;
    final String server;
    if (current == null) {
      server = 'not registered yet';
    } else if (!current.stepupKeyRegistered) {
      server = 'not bound on the server: re-enrol it with your password below';
    } else if (current.stepupKeyMatches == false) {
      server = 'the server holds a different step-up key: re-enrol it with '
          'your password below';
    } else if (_stepUpKeyOtherAccount) {
      server = 'bound to another account on this phone: re-enrol it with '
          "this account's password below";
    } else if (stepUpPolicyMismatch != null) {
      server = "the server's step-up policy changed ($stepUpPolicyMismatch): "
          're-enrol it with your password below';
    } else if (key.thumbprint != _boundStepUpThumbprint) {
      server = 'not confirmed as the bound key: re-enrol it with your '
          'password below';
    } else {
      server = 'bound on the server';
    }
    final String downgrade = current?.stepupPolicyDowngrade == true
        ? '; weaker than server policy (downgrade recorded)'
        : '';
    final StepUpPolicy? policy = stepUpPolicy;
    return 'Step-up key: ${key.description}, ${key.securityLevel}; '
        '$server$downgrade'
        '${policy == null ? '' : '\nStep-up policy: ${policy.description}'}';
  }

  Future<void> _registerAndProve() async {
    InstallationIdentity currentIdentity = identity!;
    RegistrationState currentRegistration;
    await _prepareStepUpKey();
    try {
      currentRegistration = await _api.registerInstallation(
        currentIdentity,
        reinstallHint,
        stepUpKey: stepUpKey,
      );
    } on ApiException catch (error) {
      if (error.code != 'registration_race_retry') {
        rethrow;
      }
      currentRegistration = await _api.registerInstallation(
        currentIdentity,
        reinstallHint,
        stepUpKey: stepUpKey,
      );
    }
    debugPrint(
      'STEPUP: server registered=${currentRegistration.stepupKeyRegistered} '
      'matches=${currentRegistration.stepupKeyMatches} '
      'auth=${currentRegistration.stepupKeyAuth} '
      'policy_downgrade=${currentRegistration.stepupPolicyDowngrade}',
    );

    if (currentRegistration.installationId != currentIdentity.installationId) {
      currentIdentity = currentIdentity.withInstallationId(
        currentRegistration.installationId,
      );
      identity = currentIdentity;
      await _store.saveIdentity(currentIdentity);
    }
    registration = currentRegistration;
    await _store.saveRegistration(currentRegistration);
    final StepUpKeyMetadata? offered = stepUpKey;
    _boundStepUpThumbprint = offered != null &&
            currentRegistration.stepupKeyRegistered &&
            currentRegistration.stepupKeyMatches != false
        ? offered.thumbprint
        : null;

    deviceToken = await _proveInstallation(currentIdentity);
    await _collectIntegrityWithToken(deviceToken!, currentIdentity);
    summary = await _api.deviceSummary(deviceToken!, currentIdentity);
    latestPolicy ??= summary?.policy;
  }

  Future<String> _proveInstallation(InstallationIdentity currentIdentity) async {
    final Map<String, dynamic> challenge =
        await _api.createInstallationChallenge(currentIdentity.installationId);
    final String payload = challenge['payload'] as String;
    final String signature = await currentIdentity.signPayload(payload);
    final Map<String, dynamic> verification = await _api.verifyInstallation(
      installationId: currentIdentity.installationId,
      challengeId: challenge['challenge_id'] as String,
      payload: payload,
      signature: signature,
    );
    return verification['device_token'] as String;
  }

  Future<String> _freshDeviceToken() async {
    identity ??= await _store.loadOrCreateIdentity();
    return _proveInstallation(identity!);
  }

  String _base64UrlNoPadding(List<int> bytes) {
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  Future<IntegrityDecision> _collectIntegrityWithToken(
    String token,
    InstallationIdentity currentIdentity, {
    String? testFixture,
  }) async {
    final Map<String, dynamic> challenge = await _api.integrityChallenge(
      deviceToken: token,
      signingIdentity: currentIdentity,
    );
    final String challengeId = challenge['challenge_id'] as String;
    final String nonce = challenge['nonce'] as String;
    final String platform = challenge['platform'] as String;
    final List<String> requiredProbes = (challenge['required_probes'] as List)
        .map((Object? item) => item.toString())
        .toList(growable: false);
    lastIntegrityProbes = requiredProbes;
    // Absent from a server older than DESIGN.md 80.
    final Object? optional = challenge['optional_probes'];
    final List<String> optionalProbes = optional is List
        ? optional.map((Object? item) => item.toString()).toList(growable: false)
        : const <String>[];

    lastIntegrityTestFixture = testFixture;
    final Map<String, dynamic> native = await _integrityCollector.collect(
      requiredProbes: requiredProbes,
      challengeNonce: nonce,
      testFixture: testFixture,
      optionalProbes: optionalProbes,
    );
    if (native['probes'] is! Map) {
      throw ApiException(
        'The native collector returned no probe map.',
        code: 'invalid_native_integrity_result',
      );
    }
    if (native['platform'] != platform ||
        native['challenge_nonce_echo'] != nonce) {
      throw ApiException(
        'The native integrity response did not match the server challenge.',
        code: 'integrity_challenge_binding_failed',
      );
    }

    final Map<String, dynamic> report = <String, dynamic>{
      'challenge_id': challengeId,
      'challenge_nonce': nonce,
      'installation_id': currentIdentity.installationId,
      'platform': platform,
      'collector_version': (native['collector_version'] as num?)?.toInt() ?? 1,
      'collected_at': DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
      'probe_results': Map<String, dynamic>.from(native['probes'] as Map),
      'version': 1,
    };

    final String reportPayload =
        _base64UrlNoPadding(utf8.encode(jsonEncode(report)));
    final String reportSignature =
        await currentIdentity.signPayload(reportPayload);

    final IntegrityDecision decision = await _api.submitIntegrityReport(
      deviceToken: token,
      signingIdentity: currentIdentity,
      reportPayload: reportPayload,
      reportSignature: reportSignature,
    );
    latestIntegrity = decision;
    debugPrint(
      'INTEGRITY: score=${decision.score} verdict=${decision.verdict} '
      'mode=${decision.mode} probes=${requiredProbes.join(',')}',
    );
    for (final IntegrityRiskReason reason in decision.reasons) {
      debugPrint(
        'INTEGRITY REASON: ${reason.code} +${reason.points} ${reason.message}',
      );
    }
    return decision;
  }

  Future<void> _runIntegrityAttackFixture({
    required String fixture,
    required String testName,
    required Set<String> expectedReasonCodes,
  }) {
    integrityAttackTestResult = null;
    return _run('Running $testName…', () async {
      if (!Platform.isAndroid) {
        throw ApiException(
          'These controlled integrity fixtures are currently implemented for Android.',
          code: 'android_test_only',
        );
      }
      identity ??= await _store.loadOrCreateIdentity();
      final String token = await _freshDeviceToken();
      deviceToken = token;
      final IntegrityDecision decision = await _collectIntegrityWithToken(
        token,
        identity!,
        testFixture: fixture,
      );
      final Set<String> actualCodes = decision.reasons
          .map((IntegrityRiskReason reason) => reason.code)
          .toSet();
      final Set<String> missing = expectedReasonCodes.difference(actualCodes);
      if (missing.isNotEmpty) {
        final String result = <String>[
          'FAIL: $testName',
          'Fixture: $fixture',
          'Missing expected reasons: ${missing.join(', ')}',
          'Actual reasons: ${actualCodes.join(', ')}',
          'Score: ${decision.score}',
          'Verdict: ${decision.verdict}',
        ].join('\n');
        integrityAttackTestResult = result;
        debugPrint(result);
        throw ApiException(
          '$testName did not produce the expected server reason(s).',
          code: 'integrity_fixture_test_failed',
        );
      }

      final String result = <String>[
        'PASS: $testName',
        'Fixture: $fixture',
        'Expected reasons: ${expectedReasonCodes.join(', ')}',
        'Score: ${decision.score}',
        'Verdict: ${decision.verdict}',
        'Signed native report: accepted',
        'Server challenge: accepted',
      ].join('\n');
      integrityAttackTestResult = result;
      status = 'PASS: $testName';
      debugPrint(result);
    });
  }

  Future<void> testFridaRuntimeDetection() {
    return _runIntegrityAttackFixture(
      fixture: 'frida_runtime',
      testName: '1. Frida/runtime-map detection',
      expectedReasonCodes: <String>{'android_frida_runtime_artifact'},
    );
  }

  Future<void> testFridaPortDetection() {
    return _runIntegrityAttackFixture(
      fixture: 'frida_port',
      testName: '2. Local Frida-port detection',
      expectedReasonCodes: <String>{'android_frida_port_open'},
    );
  }

  Future<void> testHookFrameworkDetection() {
    return _runIntegrityAttackFixture(
      fixture: 'hook_framework',
      testName: '3. Xposed/LSPosed/Zygisk artifact detection',
      expectedReasonCodes: <String>{'android_hook_framework_artifact'},
    );
  }

  Future<void> testRootSuDetection() {
    return _runIntegrityAttackFixture(
      fixture: 'root_su',
      testName: '4. Root/su detection',
      expectedReasonCodes: <String>{
        'android_root_framework_artifact',
        'android_su_on_path',
      },
    );
  }

  Future<void> testWritableMountDetection() {
    return _runIntegrityAttackFixture(
      fixture: 'writable_mount',
      testName: '5. Writable protected-mount detection',
      expectedReasonCodes: <String>{'android_protected_mount_writable'},
    );
  }

  Future<void> testIntegrityEnforcement() {
    integrityAttackTestResult = null;
    return _run('Running 6. enforced integrity rejection…', () async {
      final AccountSession? session = accountSession;
      if (session == null) {
        throw ApiException(
          'Create or log in to a test account first; enforcement is tested against an account-protected endpoint.',
          code: 'account_session_required',
        );
      }
      identity ??= await _store.loadOrCreateIdentity();
      final InstallationIdentity currentIdentity = identity!;
      final String token = await _freshDeviceToken();
      deviceToken = token;

      final IntegrityDecision malicious = await _collectIntegrityWithToken(
        token,
        currentIdentity,
        testFixture: 'frida_runtime',
      );
      if (malicious.verdict != 'block') {
        throw ApiException(
          'The injected Frida report did not produce a block verdict.',
          code: 'unexpected_integrity_verdict',
        );
      }

      try {
        await _api.accountMe(
          accessToken: session.accessToken,
          signingIdentity: currentIdentity,
        );
      } on ApiException catch (error) {
        if (error.statusCode == 403 && error.code == 'integrity_blocked') {
          final String result = <String>[
            'PASS: 6. INTEGRITY_MODE=enforce rejected a protected request',
            'Injected integrity verdict: ${malicious.verdict}',
            'Injected integrity score: ${malicious.score}',
            'GET /v1/account/me: 403',
            'Server error: integrity_blocked',
            'Access PoP reached server: yes',
            'Business request allowed through: no',
          ].join('\n');
          integrityAttackTestResult = result;
          status = 'PASS: enforced integrity rejection';
          debugPrint(result);
          return;
        }
        rethrow;
      }

      final String result = <String>[
        'FAIL: 6. INTEGRITY_MODE=enforce did not reject the request',
        'Injected integrity verdict: ${malicious.verdict}',
        'GET /v1/account/me: unexpectedly accepted',
      ].join('\n');
      integrityAttackTestResult = result;
      debugPrint(result);
      throw ApiException(
        'Protected request was accepted after a block integrity verdict. Is INTEGRITY_MODE=enforce on the server?',
        code: 'integrity_enforcement_test_failed',
      );
    });
  }

  /// The OS location permission this app holds, once asked (DESIGN.md 82).
  String? locationPermission;

  Future<void> allowLocation() {
    return _run('Asking for the location permission…', () async {
      locationPermission =
          await _integrityCollector.requestLocationPermission();
      status = 'Location permission: $locationPermission';
    });
  }

  Future<void> runIntegrityScan() {
    return _run('Running server-challenged native integrity scan…', () async {
      identity ??= await _store.loadOrCreateIdentity();
      final String token = await _freshDeviceToken();
      deviceToken = token;
      final IntegrityDecision decision =
          await _collectIntegrityWithToken(token, identity!);
      status =
          'Integrity verdict: ${decision.verdict} (${decision.score}/100)';
    });
  }

  Future<void> refreshSummary() {
    return _run('Refreshing the server device record…', () async {
      final String token = await _freshDeviceToken();
      deviceToken = token;
      summary = await _api.deviceSummary(token, identity!);
      if (accountSession == null) {
        latestPolicy = summary?.policy;
      }
      status = 'Device record refreshed';
    });
  }

  Future<void> createAccount(String handle, String password) {
    return _run('Creating an account on this device…', () async {
      final String token = await _freshDeviceToken();
      deviceToken = token;
      await _collectIntegrityWithToken(token, identity!);
      accountSession = await _onceMoreIfRelationshipChanged(
        () => _api.registerAccount(
          deviceToken: token,
          signingIdentity: identity!,
          handle: handle,
          password: password,
        ),
      );
      await _store.saveAccountSession(accountSession!);
      latestPolicy = accountSession?.policy;
      _stepUpKeyOtherAccount = false;
      _logSession('account created');
      summary = await _api.deviceSummary(token, identity!);
      status = 'Account created and linked to the recognized device';
    });
  }

  Future<void> loginAccount(String handle, String password) {
    return _run('Signing in and linking this device…', () async {
      final String token = await _freshDeviceToken();
      deviceToken = token;
      await _collectIntegrityWithToken(token, identity!);
      accountSession = await _onceMoreIfRelationshipChanged(
        () => _api.loginAccount(
          deviceToken: token,
          signingIdentity: identity!,
          handle: handle,
          password: password,
        ),
      );
      await _store.saveAccountSession(accountSession!);
      latestPolicy = accountSession?.policy;
      _stepUpKeyOtherAccount = false;
      _logSession('login');
      summary = await _api.deviceSummary(token, identity!);
      status = accountSession!.isLimited
          ? 'Signed in with a LIMITED session'
          : 'Account authenticated on the recognized device';
    });
  }

  /// A sign-in decided while another sign-in linked the same phone or account
  /// answers 409 relationship_changed and writes nothing (DESIGN.md 76). The
  /// app asks once more, and the server decides on the new counts; a second
  /// conflict is reported.
  Future<AccountSession> _onceMoreIfRelationshipChanged(
    Future<AccountSession> Function() signIn,
  ) async {
    try {
      return await signIn();
    } on ApiException catch (error) {
      if (error.code != 'relationship_changed') {
        rethrow;
      }
      debugPrint('SESSION: relationship changed during sign-in; asking again');
      return signIn();
    }
  }

  Future<void> refreshPolicy() {
    return _run('Evaluating the current account/device risk…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }
      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);
      latestPolicy = await _api.currentPolicy(
        accessToken: session.accessToken,
        signingIdentity: currentIdentity,
      );
      status =
          'Risk policy evaluated: ${latestPolicy!.recommendedAction} (${latestPolicy!.score})';
    });
  }

  String _jwtPayloadPart(String token) {
    final List<String> parts = token.split('.');
    if (parts.length != 3) {
      throw const FormatException('JWT does not have three parts.');
    }

    String payload = parts[1].replaceAll('-', '+').replaceAll('_', '/');
    switch (payload.length % 4) {
      case 2:
        payload += '==';
        break;
      case 3:
        payload += '=';
        break;
      case 0:
        break;
      default:
        throw const FormatException('JWT payload has invalid base64url length.');
    }
    return utf8.decode(base64.decode(payload));
  }

  String _cleanTestToken(String raw) {
    String token = raw.trim();
    if (token.length >= 2) {
      final String first = token.substring(0, 1);
      final String last = token.substring(token.length - 1);
      if ((first == '"' && last == '"') ||
          (first == "'" && last == "'")) {
        token = token.substring(1, token.length - 1).trim();
      }
    }
    return token;
  }

  String? _jwtStringClaim(String token, String claimName) {
    try {
      final Map<String, dynamic> claims = Map<String, dynamic>.from(
        jsonDecode(_jwtPayloadPart(token)) as Map,
      );
      final Object? value = claims[claimName];
      return value is String && value.isNotEmpty ? value : null;
    } catch (_) {
      // Test/display helper only. The server remains authoritative.
      return null;
    }
  }

  String _shortRefreshSessionId(String refreshToken) {
    try {
      final Map<String, dynamic> claims = Map<String, dynamic>.from(
        jsonDecode(_jwtPayloadPart(refreshToken)) as Map,
      );
      final Object? sid = claims['sid'];
      if (sid is! String || sid.isEmpty) {
        return 'unavailable';
      }
      return sid.length <= 8 ? sid : sid.substring(0, 8);
    } catch (_) {
      // This helper is for display only. JWT validity is still determined by
      // the server, never by this local decode.
      return 'unavailable';
    }
  }

  Future<void> testBoundRefresh() {
    boundRefreshTestResult = null;
    return _run('Rotating the device-bound refresh token…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }

      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);

      final String oldSessionId =
          _shortRefreshSessionId(session.refreshToken);

      // If this request returns, the refresh token was valid and the server
      // issued a challenge bound to this installation/session.
      final Map<String, dynamic> challenge =
          await _api.refreshChallenge(session.refreshToken);
      final String payload = challenge['payload'] as String;

      // The native Android/iOS key signs the exact server challenge.
      final String signature = await currentIdentity.signPayload(payload);

      // A successful response proves the server accepted that native-key
      // signature and rotated the refresh session.
      final AccountSession rotatedSession = await _api.refreshAccount(
        refreshToken: session.refreshToken,
        challengeId: challenge['challenge_id'] as String,
        payload: payload,
        signature: signature,
      );

      accountSession = rotatedSession;
      latestPolicy = rotatedSession.policy;
      await _store.saveAccountSession(rotatedSession);
      _logSession('refresh');

      // Also prove the newly issued access token is usable.
      await _api.accountMe(
        accessToken: rotatedSession.accessToken,
        signingIdentity: currentIdentity,
      );

      final String newSessionId =
          _shortRefreshSessionId(rotatedSession.refreshToken);

      final String result = <String>[
        'PASS: legitimate bound refresh succeeded',
        'Old refresh session: $oldSessionId',
        'New refresh session: $newSessionId',
        'Native installation signature: accepted',
      ].join('\n');

      boundRefreshTestResult = result;
      status = 'PASS: legitimate bound refresh succeeded';
      debugPrint(result);
    });
  }

  Future<void> copyRefreshTokenForAttackTest() {
    return _run('Exposing the refresh token for the controlled attack test…', () async {
      final AccountSession? session = accountSession;
      if (session == null) {
        throw ApiException('Create or log in to an account first.');
      }

      await Clipboard.setData(ClipboardData(text: session.refreshToken));
      debugPrint('STOLEN_REFRESH_TOKEN=${session.refreshToken}');
      status =
          'TEST ONLY: refresh token copied to clipboard and printed to the Flutter console';
    });
  }

  Future<void> testStolenRefreshToken(String stolenRefreshToken) {
    stolenRefreshTestResult = null;
    return _run(
      'Attempting to use a refresh token stolen from another installation…',
      () async {
        final String token = _cleanTestToken(stolenRefreshToken);
        if (token.isEmpty) {
          throw ApiException('Paste or inject Phone A\'s refresh token first.');
        }

        identity ??= await _store.loadOrCreateIdentity();
        final InstallationIdentity currentIdentity = identity!;

        int? challengeStatus;
        int? refreshStatus;
        String? serverError;

        try {
          // If this returns, Phone A's stolen refresh token itself is valid.
          final Map<String, dynamic> challenge =
              await _api.refreshChallenge(token);
          challengeStatus = 200;

          final String payload = challenge['payload'] as String;

          // Deliberately sign Phone A's challenge with Phone B's native key.
          final String signature = await currentIdentity.signPayload(payload);

          try {
            await _api.refreshAccount(
              refreshToken: token,
              challengeId: challenge['challenge_id'] as String,
              payload: payload,
              signature: signature,
            );

            // Reaching here means the wrong installation key was accepted.
            refreshStatus = 200;
            serverError = 'none';
            final String result = <String>[
              'FAIL: stolen refresh token was accepted',
              'Challenge request: $challengeStatus',
              'Refresh request: $refreshStatus',
              'Server error: $serverError',
            ].join('\n');
            stolenRefreshTestResult = result;
            debugPrint(result);
            throw ApiException(
              'SECURITY TEST FAILED: the server accepted a refresh token with the wrong installation key.',
              statusCode: 200,
              code: 'stolen_refresh_accepted',
            );
          } on ApiException catch (error) {
            // Do not accidentally treat our deliberate failure exception above
            // as a successful security result.
            if (error.code == 'stolen_refresh_accepted') {
              rethrow;
            }

            refreshStatus = error.statusCode;
            serverError = error.code ?? 'unknown';

            if (error.statusCode == 401 &&
                error.code == 'invalid_installation_signature') {
              final String result = <String>[
                'PASS: stolen refresh rejected',
                'Challenge request: $challengeStatus',
                'Refresh request: $refreshStatus',
                'Server error: $serverError',
              ].join('\n');

              stolenRefreshTestResult = result;
              status = 'PASS: stolen refresh rejected';
              debugPrint(result);
              return;
            }

            final String result = <String>[
              'INCONCLUSIVE: stolen refresh was rejected for an unexpected reason',
              'Challenge request: $challengeStatus',
              'Refresh request: ${refreshStatus ?? 'no response'}',
              'Server error: $serverError',
            ].join('\n');
            stolenRefreshTestResult = result;
            debugPrint(result);
            rethrow;
          }
        } on ApiException catch (error) {
          // A failure here means the stolen token did not even reach the
          // proof-of-possession stage (for example, quotes were pasted around
          // the JWT, or the token was expired/revoked).
          if (challengeStatus == null) {
            final String result = <String>[
              'INCONCLUSIVE: refresh challenge was rejected before key proof',
              'Challenge request: ${error.statusCode ?? 'no response'}',
              'Refresh request: not attempted',
              'Server error: ${error.code ?? 'unknown'}',
            ].join('\n');
            stolenRefreshTestResult = result;
            debugPrint(result);
          }
          rethrow;
        }
      },
    );
  }

  Future<void> testBoundAccessProof() {
    boundAccessTestResult = null;
    return _run('Testing proof-of-possession on ordinary API requests…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }

      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);

      final Map<String, dynamic> me = await _api.accountMe(
        accessToken: session.accessToken,
        signingIdentity: currentIdentity,
      );

      final String probeId = Uuid().v4();
      final Map<String, dynamic> echo = await _api.protectedEcho(
        accessToken: session.accessToken,
        signingIdentity: currentIdentity,
        body: <String, dynamic>{
          'probe_id': probeId,
          'message': 'proof-of-possession body binding test',
        },
      );

      final Map<String, dynamic>? echoedBody = echo['echo'] is Map
          ? Map<String, dynamic>.from(echo['echo'] as Map)
          : null;
      if (me['access_proof'] != 'accepted' ||
          echo['access_proof'] != 'accepted' ||
          echoedBody?['probe_id'] != probeId) {
        throw ApiException(
          'The protected API returned an unexpected proof result.',
          code: 'unexpected_access_proof_result',
        );
      }

      final String result = <String>[
        'PASS: legitimate access proof accepted',
        'GET /v1/account/me: 200',
        'POST /v1/account/protected-echo: 200',
        'Access token SHA-256: bound',
        'HTTP method and path: bound',
        'Request body SHA-256: accepted',
        'Timestamp window: accepted',
        'One-time nonce: accepted',
        'Native installation signature: accepted',
      ].join('\n');

      boundAccessTestResult = result;
      status = 'PASS: legitimate access proof accepted';
      debugPrint(result);
    });
  }

  Future<void> copyAccessTokenForAttackTest() {
    return _run('Exposing the access token for the controlled attack test…', () async {
      final AccountSession? session = accountSession;
      if (session == null) {
        throw ApiException('Create or log in to an account first.');
      }

      await Clipboard.setData(ClipboardData(text: session.accessToken));
      debugPrint('STOLEN_ACCESS_TOKEN=${session.accessToken}');
      status =
          'TEST ONLY: access token copied to clipboard and printed to the Flutter console';
    });
  }

  Future<void> testStolenAccessToken(String stolenAccessToken) {
    stolenAccessTestResult = null;
    return _run(
      'Attempting a protected API call with an access token stolen from another installation…',
      () async {
        final String token = _cleanTestToken(stolenAccessToken);
        if (token.isEmpty) {
          throw ApiException('Paste or inject Phone A\'s access token first.');
        }

        identity ??= await _store.loadOrCreateIdentity();
        final InstallationIdentity currentIdentity = identity!;
        final String? tokenInstallationId = _jwtStringClaim(token, 'iid');
        if (tokenInstallationId == null) {
          final String result = <String>[
            'INCONCLUSIVE: stolen access token could not be decoded locally',
            'Protected request: not attempted',
            'Server error: not reached',
          ].join('\n');
          stolenAccessTestResult = result;
          debugPrint(result);
          throw ApiException('The stolen access token has no installation binding.');
        }

        try {
          // Use Phone A's iid from the stolen token in the proof payload, but
          // sign that payload with Phone B's native key. This isolates the
          // cryptographic possession test rather than failing on iid mismatch.
          await _api.accountMe(
            accessToken: token,
            signingIdentity: currentIdentity,
            proofInstallationId: tokenInstallationId,
          );

          final String result = <String>[
            'FAIL: stolen access token was accepted',
            'Protected request: 200',
            'Server error: none',
          ].join('\n');
          stolenAccessTestResult = result;
          debugPrint(result);
          throw ApiException(
            'SECURITY TEST FAILED: the server accepted an access token with the wrong installation key.',
            statusCode: 200,
            code: 'stolen_access_accepted',
          );
        } on ApiException catch (error) {
          if (error.code == 'stolen_access_accepted') {
            rethrow;
          }

          if (error.statusCode == 401 &&
              error.code == 'invalid_installation_signature') {
            final String result = <String>[
              'PASS: stolen access token rejected',
              'Protected request: 401',
              'Server error: invalid_installation_signature',
              'Access token reached proof verification: yes',
              'Wrong native installation key: rejected',
            ].join('\n');
            stolenAccessTestResult = result;
            status = 'PASS: stolen access token rejected';
            debugPrint(result);
            return;
          }

          final String result = <String>[
            'INCONCLUSIVE: stolen access token was rejected for another reason',
            'Protected request: ${error.statusCode ?? 'no response'}',
            'Server error: ${error.code ?? 'unknown'}',
          ].join('\n');
          stolenAccessTestResult = result;
          debugPrint(result);
          rethrow;
        }
      },
    );
  }

  Future<void> testAccessProofReplay() {
    replayAttackTestResult = null;
    return _run('Testing exact signed-request replay protection…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }

      final String probeId = Uuid().v4();
      final AccessProofFixture fixture = await _api.buildAccessProofFixture(
        'POST',
        '/v1/account/protected-echo',
        bearerToken: session.accessToken,
        signingIdentity: currentIdentity,
        body: <String, dynamic>{
          'probe_id': probeId,
          'message': 'replay protection test',
        },
      );

      final Map<String, dynamic> first =
          await _api.sendAccessProofFixture(fixture);
      if (first['access_proof'] != 'accepted') {
        throw ApiException(
          'The control request was not accepted.',
          code: 'replay_control_failed',
        );
      }

      try {
        await _api.sendAccessProofFixture(fixture);
        final String result = <String>[
          'FAIL: exact signed request was replayed successfully',
          'First request: 200',
          'Replay request: 200',
          'Expected server error: access_proof_replay',
        ].join('\n');
        replayAttackTestResult = result;
        debugPrint(result);
        throw ApiException(
          'SECURITY TEST FAILED: replayed proof was accepted.',
          statusCode: 200,
          code: 'access_proof_replay_accepted',
        );
      } on ApiException catch (error) {
        if (error.code == 'access_proof_replay_accepted') {
          rethrow;
        }
        if (error.statusCode == 401 && error.code == 'access_proof_replay') {
          final String result = <String>[
            'PASS: exact signed-request replay rejected',
            'First request: 200',
            'Replay request: 401',
            'Server error: access_proof_replay',
            'Same proof: reused',
            'Same native signature: reused',
            'Same nonce: reused and rejected',
          ].join('\n');
          replayAttackTestResult = result;
          status = 'PASS: replay protection accepted first request and rejected replay';
          debugPrint(result);
          return;
        }
        final String result = <String>[
          'INCONCLUSIVE: replay request failed for another reason',
          'First request: 200',
          'Replay request: ${error.statusCode ?? 'no response'}',
          'Server error: ${error.code ?? 'unknown'}',
        ].join('\n');
        replayAttackTestResult = result;
        debugPrint(result);
        rethrow;
      }
    });
  }

  Future<void> testAccessProofBodyTampering() {
    bodyTamperTestResult = null;
    return _run('Testing request-body tampering protection…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }

      final String probeId = Uuid().v4();
      final Map<String, dynamic> signedBody = <String, dynamic>{
        'probe_id': probeId,
        'message': 'ORIGINAL body signed by the native key',
      };
      final Map<String, dynamic> tamperedBody = <String, dynamic>{
        'probe_id': probeId,
        'message': 'TAMPERED after the proof was signed',
      };

      final AccessProofFixture fixture = await _api.buildAccessProofFixture(
        'POST',
        '/v1/account/protected-echo',
        bearerToken: session.accessToken,
        signingIdentity: currentIdentity,
        body: signedBody,
      );

      try {
        await _api.sendAccessProofFixture(
          fixture,
          actualEncodedBody: jsonEncode(tamperedBody),
        );
        final String result = <String>[
          'FAIL: tampered request body was accepted',
          'Protected request: 200',
          'Expected server error: access_proof_body_mismatch',
        ].join('\n');
        bodyTamperTestResult = result;
        debugPrint(result);
        throw ApiException(
          'SECURITY TEST FAILED: changed body was accepted.',
          statusCode: 200,
          code: 'tampered_body_accepted',
        );
      } on ApiException catch (error) {
        if (error.code == 'tampered_body_accepted') {
          rethrow;
        }
        if (error.statusCode == 401 &&
            error.code == 'access_proof_body_mismatch') {
          final String result = <String>[
            'PASS: body tampering rejected',
            'Protected request: 401',
            'Server error: access_proof_body_mismatch',
            'Proof signed hash: original body',
            'HTTP body sent: modified after signing',
          ].join('\n');
          bodyTamperTestResult = result;
          status = 'PASS: request-body tampering rejected';
          debugPrint(result);
          return;
        }
        final String result = <String>[
          'INCONCLUSIVE: body-tampering request failed for another reason',
          'Protected request: ${error.statusCode ?? 'no response'}',
          'Server error: ${error.code ?? 'unknown'}',
        ].join('\n');
        bodyTamperTestResult = result;
        debugPrint(result);
        rethrow;
      }
    });
  }

  Future<void> testAccessProofPathAndMethodTampering() {
    pathMethodTamperTestResult = null;
    return _run('Testing HTTP path and method binding…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }

      int? pathStatus;
      String? pathCode;
      int? methodStatus;
      String? methodCode;

      // PATH TEST: sign a proof naming another path, then send that exact proof
      // to the real GET /v1/account/me endpoint.
      final AccessProofFixture wrongPathFixture =
          await _api.buildAccessProofFixture(
        'GET',
        '/v1/account/not-the-requested-route',
        bearerToken: session.accessToken,
        signingIdentity: currentIdentity,
      );
      try {
        await _api.sendAccessProofFixture(
          wrongPathFixture,
          actualMethod: 'GET',
          actualPath: '/v1/account/me',
        );
        pathStatus = 200;
        pathCode = 'accepted';
      } on ApiException catch (error) {
        pathStatus = error.statusCode;
        pathCode = error.code;
      }

      // METHOD TEST: sign a GET proof for the real protected-echo path, then
      // actually POST to that path. Method mismatch is checked before body hash.
      final AccessProofFixture wrongMethodFixture =
          await _api.buildAccessProofFixture(
        'GET',
        '/v1/account/protected-echo',
        bearerToken: session.accessToken,
        signingIdentity: currentIdentity,
      );
      try {
        await _api.sendAccessProofFixture(
          wrongMethodFixture,
          actualMethod: 'POST',
          actualPath: '/v1/account/protected-echo',
          actualEncodedBody: jsonEncode(<String, dynamic>{
            'message': 'actual POST while proof says GET',
          }),
        );
        methodStatus = 200;
        methodCode = 'accepted';
      } on ApiException catch (error) {
        methodStatus = error.statusCode;
        methodCode = error.code;
      }

      final bool pathPassed = pathStatus == 401 &&
          pathCode == 'access_proof_path_mismatch';
      final bool methodPassed = methodStatus == 401 &&
          methodCode == 'access_proof_method_mismatch';

      if (pathPassed && methodPassed) {
        final String result = <String>[
          'PASS: HTTP path and method tampering rejected',
          'Path-tampered request: 401',
          'Path server error: access_proof_path_mismatch',
          'Method-tampered request: 401',
          'Method server error: access_proof_method_mismatch',
        ].join('\n');
        pathMethodTamperTestResult = result;
        status = 'PASS: HTTP path and method are cryptographically bound';
        debugPrint(result);
        return;
      }

      final String result = <String>[
        'FAIL/INCONCLUSIVE: path or method binding did not return the expected result',
        'Path request: ${pathStatus ?? 'no response'}',
        'Path server error: ${pathCode ?? 'unknown'}',
        'Method request: ${methodStatus ?? 'no response'}',
        'Method server error: ${methodCode ?? 'unknown'}',
      ].join('\n');
      pathMethodTamperTestResult = result;
      debugPrint(result);
      throw ApiException(
        'Path/method tampering test did not produce both expected rejections.',
        code: 'path_method_test_failed',
      );
    });
  }

  Future<void> testExpiredAccessProofTimestamp() {
    timestampExpiryTestResult = null;
    return _run('Testing the access-proof timestamp window…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }

      final int nowSeconds =
          DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
      // Server permits at most 120 seconds of skew. A proof timestamped 180
      // seconds ago is equivalent to replaying a captured proof after expiry,
      // without making this UI sit idle for two minutes.
      const int simulatedAgeSeconds = 180;
      final AccessProofFixture staleFixture =
          await _api.buildAccessProofFixture(
        'GET',
        '/v1/account/me',
        bearerToken: session.accessToken,
        signingIdentity: currentIdentity,
        timestampSeconds: nowSeconds - simulatedAgeSeconds,
      );

      try {
        await _api.sendAccessProofFixture(staleFixture);
        final String result = <String>[
          'FAIL: stale access proof was accepted',
          'Protected request: 200',
          'Proof age: $simulatedAgeSeconds seconds',
          'Server window: 120 seconds',
        ].join('\n');
        timestampExpiryTestResult = result;
        debugPrint(result);
        throw ApiException(
          'SECURITY TEST FAILED: stale proof was accepted.',
          statusCode: 200,
          code: 'stale_access_proof_accepted',
        );
      } on ApiException catch (error) {
        if (error.code == 'stale_access_proof_accepted') {
          rethrow;
        }
        if (error.statusCode == 401 &&
            error.code == 'access_proof_timestamp_outside_window') {
          final String result = <String>[
            'PASS: stale access proof rejected',
            'Protected request: 401',
            'Server error: access_proof_timestamp_outside_window',
            'Proof age: $simulatedAgeSeconds seconds',
            'Server allowed skew: 120 seconds',
          ].join('\n');
          timestampExpiryTestResult = result;
          status = 'PASS: stale access proof rejected';
          debugPrint(result);
          return;
        }
        final String result = <String>[
          'INCONCLUSIVE: stale-proof request failed for another reason',
          'Protected request: ${error.statusCode ?? 'no response'}',
          'Server error: ${error.code ?? 'unknown'}',
        ].join('\n');
        timestampExpiryTestResult = result;
        debugPrint(result);
        rethrow;
      }
    });
  }

  void _recordStepUp(List<String> lines) {
    stepUpTestResult = lines.join('\n');
    status = lines.first;
    for (final String line in lines) {
      debugPrint('STEPUP: $line');
    }
  }

  /// The gate: without a step-up proof a gated sensitive path must be refused.
  Future<void> testSensitiveWithoutStepUp() {
    stepUpTestResult = null;
    return _run('Calling the sensitive operation without step-up…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }
      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);
      try {
        final Map<String, dynamic> value = await _api.sensitiveEcho(
          accessToken: session.accessToken,
          signingIdentity: currentIdentity,
          body: <String, dynamic>{
            'operation': 'transfer',
            'probe_id': Uuid().v4(),
          },
        );
        _recordStepUp(<String>[
          value['step_up'] == 'not_required'
              ? 'INFO: the server does not gate this path (stepup_required_paths)'
              : 'FAIL: accepted without a step-up proof',
          'POST /v1/account/sensitive-echo: 200 step_up=${value['step_up']}',
        ]);
      } on ApiException catch (error) {
        final bool refused = error.statusCode == 403 &&
            (error.code == 'stepup_required' ||
                error.code == 'stepup_key_not_registered');
        _recordStepUp(<String>[
          refused
              ? 'PASS: sensitive operation refused without step-up'
              : 'FAIL: unexpected rejection',
          'POST /v1/account/sensitive-echo: ${error.statusCode} ${error.code}',
        ]);
      }
    });
  }

  /// The app PIN typed into the harness (DESIGN.md 78). Sent with every
  /// step-up -- sensitive op, approval, route-1 upgrade -- when filled; the
  /// server checks it where the DBA's stepup_method or app_pin_required_paths
  /// ask, and verifies an offered one anywhere.
  String appPinEntry = '';

  String? get _appPinOrNull => appPinEntry.isEmpty ? null : appPinEntry;

  void updateAppPinEntry(String value) {
    appPinEntry = value.trim();
    notifyListeners();
  }

  /// Sets or replaces the account's app PIN with the account password.
  Future<void> setAppPin(String password) {
    stepUpTestResult = null;
    return _run('Setting the app PIN…', () async {
      final InstallationIdentity? currentIdentity = identity;
      if (accountSession == null || currentIdentity == null) {
        throw ApiException('Log in first: the app PIN belongs to the account.');
      }
      if (appPinEntry.isEmpty) {
        throw ApiException('Type the new app PIN first.');
      }
      try {
        final Map<String, dynamic> value = await _withAccessToken(
          (String accessToken) => _api.setAppPin(
            accessToken: accessToken,
            signingIdentity: currentIdentity,
            password: password,
            pin: appPinEntry,
          ),
        );
        _recordStepUp(<String>[
          'PASS: app PIN set',
          'POST /v1/account/app-pin: 200',
          'Server: ${value['step_up']}',
        ]);
      } on ApiException catch (error) {
        _recordStepUp(<String>[
          'NOT SET: ${error.code}',
          'POST /v1/account/app-pin: ${error.statusCode} ${error.code}',
        ]);
      }
    });
  }

  /// The app PIN alone (stepup_method app_pin, or a path the DBA lists in
  /// app_pin_required_paths): no screen-lock prompt.
  Future<void> testSensitiveWithAppPin() {
    stepUpTestResult = null;
    return _run('Calling the sensitive operation with the app PIN…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }
      if (appPinEntry.isEmpty) {
        throw ApiException('Type the app PIN first.');
      }
      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);
      try {
        final Map<String, dynamic> value = await _api.sensitiveEcho(
          accessToken: session.accessToken,
          signingIdentity: currentIdentity,
          body: <String, dynamic>{
            'operation': 'transfer',
            'probe_id': Uuid().v4(),
          },
          appPin: appPinEntry,
        );
        _recordStepUp(<String>[
          value['app_pin'] == 'verified'
              ? 'PASS: app PIN verified, sensitive operation allowed'
              : 'INFO: 200, but the app PIN was not needed here',
          'POST /v1/account/sensitive-echo: 200 step_up=${value['step_up']} '
              'app_pin=${value['app_pin']}',
        ]);
      } on ApiException catch (error) {
        final Object? left = error.details?['attempts_left'];
        final Object? stepUp = error.details?['step_up'];
        _recordStepUp(<String>[
          'REFUSED: ${error.code}',
          'POST /v1/account/sensitive-echo: ${error.statusCode} ${error.code}',
          if (left != null) 'Attempts left: $left',
          if (stepUp != null) 'Needs: $stepUp',
          if (error.code == 'app_pin_locked')
            'Set a new PIN with the account password to unlock it.',
        ]);
      }
    });
  }

  /// The legitimate path: the user authenticates, the step-up key signs this
  /// exact request (proof v2: token, method, path, body digest and the access
  /// proof's nonce), and the server allows it.
  Future<void> testSensitiveWithStepUp() {
    stepUpTestResult = null;
    return _run('Waiting for step-up authentication…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      final StepUpKeyMetadata? key = stepUpKey;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }
      if (key == null) {
        throw ApiException(
          'No step-up key on this device: ${stepUpUnavailable ?? 'unknown'}',
        );
      }
      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);
      final Stopwatch prompt = Stopwatch();
      try {
        final Map<String, dynamic> value = await _api.sensitiveEcho(
          accessToken: session.accessToken,
          signingIdentity: currentIdentity,
          body: <String, dynamic>{
            'operation': 'transfer',
            'probe_id': Uuid().v4(),
          },
          stepUpFactor: key.factor,
          signStepUp: (String payload) async {
            prompt.start();
            final String signature = await _stepUpKeyProvider.sign(
              payload,
              reason: 'Approve a sensitive operation (step-up test)',
            );
            prompt.stop();
            return signature;
          },
          appPin: _appPinOrNull,
        );
        final Map<String, dynamic>? seen = value['step_up_key'] is Map
            ? Map<String, dynamic>.from(value['step_up_key'] as Map)
            : null;
        _recordStepUp(<String>[
          value['step_up'] == 'verified'
              ? 'PASS: step-up verified, sensitive operation allowed'
              : 'INFO: 200 but the path is not gated (step_up=${value['step_up']})',
          'POST /v1/account/sensitive-echo: 200',
          'Prompt answered in ${prompt.elapsedMilliseconds} ms',
          'Key: ${key.description} (${key.securityLevel})',
          'Server saw key auth: ${seen?['key_auth']}',
          'Policy downgrade: ${seen?['policy_downgrade']}',
        ]);
      } on NativeKeyException catch (error) {
        if (error.code == 'STEPUP_KEY_INVALIDATED') {
          // The native side has removed the dead key; stop offering it.
          stepUpKey = null;
          stepUpUnavailable = '${error.message} [${error.code}]';
        }
        _recordStepUp(<String>[
          switch (error.code) {
            'STEPUP_CANCELLED' =>
              'CANCELLED: no step-up signature was produced; nothing was sent',
            'STEPUP_KEY_INVALIDATED' =>
              'FAIL: the step-up key is dead; re-enrol ("Simulate fresh installation")',
            _ => 'FAIL: the step-up key could not sign',
          },
          '${error.message} [${error.code}]',
        ]);
      } on ApiException catch (error) {
        _noteStepUpRefusal(error);
        _recordStepUp(<String>[
          'FAIL: the server refused the step-up proof',
          'POST /v1/account/sensitive-echo: ${error.statusCode} ${error.code}',
        ]);
      }
    });
  }

  String get sessionScopeLine {
    final AccountSession? session = accountSession;
    if (session == null) {
      return 'Session: not signed in';
    }
    if (session.isLimited) {
      final String routes = session.upgradeRoutes.isEmpty
          ? 'none - contact support'
          : session.upgradeRoutes.join(', ');
      return 'Session: LIMITED (${session.limitedCauses.join(', ')}); '
          'upgrade routes open: $routes';
    }
    if (session.acceptedCauses.isNotEmpty) {
      return 'Session: full; the upgrade accepted '
          '${session.acceptedCauses.join(', ')} until ${session.acceptedUntil}';
    }
    return 'Session: full';
  }

  void _logSession(String event) {
    debugPrint('SESSION: $event: $sessionScopeLine');
  }

  void _recordLimited(List<String> lines) {
    limitedSessionResult = lines.join('\n');
    status = lines.first;
    for (final String line in lines) {
      debugPrint('LIMITED: $line');
    }
  }

  /// Upgrade without a proof: the server re-checks and succeeds once no soft
  /// cause remains, for example after a new clean integrity scan.
  Future<void> upgradeByRecheck() => _upgrade('recheck');

  /// Route 1: a step-up on this same phone (only where the DBA enabled it,
  /// and only for integrity causes).
  Future<void> upgradeWithStepUp() => _upgrade('stepup', withStepUp: true);

  /// True while this phone waits for its approval request to be answered.
  bool waitingForApproval = false;
  DateTime? approvalExpiresAt;

  /// Stops waiting; the request stays on the server until it expires.
  void stopWaitingForApproval() {
    pendingUpgradeRequestId = null;
    waitingForApproval = false;
    _recordLimited(<String>['Stopped waiting for the approval']);
    notifyListeners();
  }

  /// Route 2, last step, done by the app itself: it asks the server every
  /// five seconds -- never faster (INTEGRATION_GUIDE.md section 7) -- until the
  /// other phone approves (the upgrade completes at once), denies, or the
  /// request expires. Before an approval exists each check is a cheap read on
  /// the server that stores no risk decision. A real app could be woken by a
  /// push notification from the customer's servers instead.
  Future<void> _waitForApproval(String requestId) async {
    waitingForApproval = true;
    notifyListeners();
    try {
      while (pendingUpgradeRequestId == requestId) {
        await Future<void>.delayed(const Duration(seconds: 5));
        if (pendingUpgradeRequestId != requestId) {
          return;
        }
        final DateTime? expires = approvalExpiresAt;
        if (expires != null && DateTime.now().toUtc().isAfter(expires)) {
          pendingUpgradeRequestId = null;
          _recordLimited(<String>[
            'EXPIRED: nobody approved in time; ask again if you still need it',
          ]);
          return;
        }
        final AccountSession? session = accountSession;
        final InstallationIdentity? currentIdentity = identity;
        if (session == null || currentIdentity == null) {
          pendingUpgradeRequestId = null;
          return;
        }
        try {
          final AccountSession upgraded = await _api.upgradeSession(
            accessToken: session.accessToken,
            signingIdentity: currentIdentity,
            route: 'approval',
            requestId: requestId,
          );
          accountSession = upgraded;
          latestPolicy = upgraded.policy ?? latestPolicy;
          await _store.saveAccountSession(upgraded);
          pendingUpgradeRequestId = null;
          _recordLimited(<String>[
            'PASS: session upgraded (approval)',
            'POST /v1/auth/upgrade: 200 scope=${upgraded.scope}',
            upgraded.acceptedCauses.isEmpty
                ? 'Accepted: nothing (no soft cause remained)'
                : 'Accepted: ${upgraded.acceptedCauses.join(', ')} '
                    'until ${upgraded.acceptedUntil}',
          ]);
          _logSession('upgrade');
          return;
        } on ApiException catch (error) {
          final Object? state = error.details?['state'];
          if (error.code == 'approval_not_granted' && state == 'pending') {
            continue;
          }
          if (error.code == 'integrity_scan_required') {
            // The scan from sign-in has aged out; take a fresh one and go on.
            final String token = await _freshDeviceToken();
            deviceToken = token;
            await _collectIntegrityWithToken(token, currentIdentity);
            continue;
          }
          pendingUpgradeRequestId = null;
          _recordLimited(<String>[
            state == 'denied'
                ? 'DENIED: the other phone refused this sign-in'
                : 'NOT UPGRADED: ${error.code}',
            'POST /v1/auth/upgrade: ${error.statusCode} ${error.code}'
                '${state == null ? '' : ' state=$state'}',
          ]);
          return;
        }
      }
    } catch (error) {
      pendingUpgradeRequestId = null;
      _recordLimited(<String>['Stopped waiting: $error']);
    } finally {
      waitingForApproval = false;
      notifyListeners();
    }
  }

  Future<void> _upgrade(
    String route, {
    bool withStepUp = false,
    String? requestId,
  }) {
    limitedSessionResult = null;
    return _run('Upgrading the session ($route)…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      final StepUpKeyMetadata? key = stepUpKey;
      if (session == null || currentIdentity == null) {
        throw ApiException('Log in first.');
      }
      final bool withKey = withStepUp && key != null && stepUpUsable;
      if (withStepUp && !withKey && _appPinOrNull == null) {
        throw ApiException(
          'No bound step-up key on this phone, and no app PIN typed: '
          '${stepUpUnavailable ?? 're-enrol the key, or type the PIN'}',
        );
      }
      // A fresh scan first, so the server judges the phone as it is now.
      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);
      try {
        final AccountSession upgraded = await _api.upgradeSession(
          accessToken: session.accessToken,
          signingIdentity: currentIdentity,
          route: route,
          requestId: requestId,
          stepUpFactor: withKey ? key.factor : null,
          signStepUp: withKey
              ? (String payload) => _stepUpKeyProvider.sign(
                    payload,
                    reason: 'Upgrade this limited session',
                  )
              : null,
          appPin: withStepUp ? _appPinOrNull : null,
        );
        accountSession = upgraded;
        latestPolicy = upgraded.policy ?? latestPolicy;
        await _store.saveAccountSession(upgraded);
        if (route == 'approval') {
          pendingUpgradeRequestId = null;
        }
        _recordLimited(<String>[
          'PASS: session upgraded ($route)',
          'POST /v1/auth/upgrade: 200 scope=${upgraded.scope}',
          upgraded.acceptedCauses.isEmpty
              ? 'Accepted: nothing (no soft cause remained)'
              : 'Accepted: ${upgraded.acceptedCauses.join(', ')} '
                  'until ${upgraded.acceptedUntil}',
        ]);
        _logSession('upgrade');
      } on NativeKeyException catch (error) {
        _recordLimited(<String>[
          error.code == 'STEPUP_CANCELLED'
              ? 'CANCELLED: no step-up signature was produced; nothing was sent'
              : 'FAIL: the step-up key could not sign',
          '${error.message} [${error.code}]',
        ]);
      } on ApiException catch (error) {
        _noteStepUpRefusal(error);
        final Object? state = error.details?['state'];
        final Object? causes = error.details?['limited_causes'];
        final Object? routes = error.details?['upgrade_routes'];
        _recordLimited(<String>[
          'NOT UPGRADED: ${error.code}',
          'POST /v1/auth/upgrade: ${error.statusCode} ${error.code}'
              '${state == null ? '' : ' state=$state'}',
          if (causes != null) 'Still limited by: $causes',
          if (routes != null) 'Routes open: $routes',
        ]);
      }
    });
  }

  /// Route 2, first step: ask another phone of this account to approve.
  Future<void> requestApproval() async {
    limitedSessionResult = null;
    await _run('Asking another phone to approve…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Log in first.');
      }
      try {
        final Map<String, dynamic> value = await _api.requestUpgrade(
          accessToken: session.accessToken,
          signingIdentity: currentIdentity,
          route: 'approval',
        );
        pendingUpgradeRequestId = value['request_id'] as String?;
        approvalExpiresAt =
            DateTime.tryParse(value['expires_at'] as String? ?? '')?.toUtc();
        _recordLimited(<String>[
          'Approval requested: $pendingUpgradeRequestId',
          'Approve it on another phone signed in to this account; this phone '
              'completes the upgrade by itself as soon as it is approved.',
          'Expires: ${value['expires_at']}',
        ]);
      } on ApiException catch (error) {
        _recordLimited(<String>[
          'NOT REQUESTED: ${error.code}',
          'POST /v1/auth/upgrade/request: ${error.statusCode} ${error.code}',
        ]);
      }
    });
    final String? requestId = pendingUpgradeRequestId;
    if (requestId != null && !waitingForApproval) {
      unawaited(_waitForApproval(requestId));
    }
  }

  /// Approver side: pending requests from this account's other phones.
  Future<void> loadApprovalRequests() {
    limitedSessionResult = null;
    return _run('Loading approval requests…', () async {
      final InstallationIdentity? currentIdentity = identity;
      if (accountSession == null || currentIdentity == null) {
        throw ApiException('Log in first.');
      }
      try {
        approvalRequests = await _withAccessToken(
          (String accessToken) => _api.pendingApprovals(
            accessToken: accessToken,
            signingIdentity: currentIdentity,
          ),
        );
        _recordLimited(<String>[
          'Approval requests waiting: ${approvalRequests.length}',
          for (final Map<String, dynamic> request in approvalRequests)
            _describeApprovalRequest(request),
        ]);
      } on ApiException catch (error) {
        approvalRequests = <Map<String, dynamic>>[];
        _recordLimited(<String>[
          'NOT LISTED: ${error.code}',
          'GET /v1/auth/approvals: ${error.statusCode} ${error.code}',
        ]);
      }
    });
  }

  /// The server's list again after an approve or deny -- whatever the answer --
  /// so a request that was used, lapsed or replaced does not linger on screen.
  Future<void> _reloadApprovalRequests(
    InstallationIdentity currentIdentity,
  ) async {
    try {
      approvalRequests = await _withAccessToken(
        (String accessToken) => _api.pendingApprovals(
          accessToken: accessToken,
          signingIdentity: currentIdentity,
        ),
      );
    } on ApiException catch (error) {
      debugPrint('LIMITED: list not reloaded: ${error.code}');
    }
  }

  /// Runs [call] with an access token that has not expired. Access tokens
  /// live ten minutes; one that is about to expire is renewed first with a
  /// bound refresh -- before anything asks for the screen lock -- and a call
  /// refused with expired_token is renewed and tried once more. Found on the
  /// Huawei, 2026-10-12: the approvals list answered expired_token after ten
  /// idle minutes.
  Future<T> _withAccessToken<T>(
    Future<T> Function(String accessToken) call,
  ) async {
    final AccountSession? session = accountSession;
    if (session == null) {
      throw ApiException('Log in first.');
    }
    if (!_accessTokenExpiring(session.accessToken)) {
      try {
        return await call(session.accessToken);
      } on ApiException catch (error) {
        if (error.code != 'expired_token') {
          rethrow;
        }
      }
    }
    final AccountSession renewed = await _renewSession();
    return call(renewed.accessToken);
  }

  /// Whether the access token's own expiry is within 30 seconds. Read from
  /// the token for timing only; the server alone decides validity.
  bool _accessTokenExpiring(String accessToken) {
    final List<String> parts = accessToken.split('.');
    if (parts.length != 3) {
      return false;
    }
    try {
      final Object? claims = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))),
      );
      final Object? exp = claims is Map ? claims['exp'] : null;
      if (exp is! num) {
        return false;
      }
      final DateTime expires =
          DateTime.fromMillisecondsSinceEpoch(exp.toInt() * 1000, isUtc: true);
      return DateTime.now()
          .toUtc()
          .add(const Duration(seconds: 30))
          .isAfter(expires);
    } on FormatException {
      return false;
    }
  }

  /// A fresh scan, then one bound refresh of the stored session; the rotated
  /// session is saved and its risk decision becomes the current one.
  Future<AccountSession> _renewSession() async {
    final InstallationIdentity? currentIdentity = identity;
    if (accountSession == null || currentIdentity == null) {
      throw ApiException('Log in first.');
    }
    final String token = await _freshDeviceToken();
    deviceToken = token;
    await _collectIntegrityWithToken(token, currentIdentity);
    final AccountSession renewed = await _rotateSession(currentIdentity);
    _logSession('renewed');
    return renewed;
  }

  /// The refresh itself: the server's challenge for the stored refresh token,
  /// signed by the installation key, then the rotation. The caller has just
  /// scanned. Saves the rotated session and its decision.
  Future<AccountSession> _rotateSession(
    InstallationIdentity currentIdentity,
  ) async {
    final AccountSession? session = accountSession;
    if (session == null) {
      throw ApiException('Log in first.');
    }
    final Map<String, dynamic> challenge =
        await _api.refreshChallenge(session.refreshToken);
    final String payload = challenge['payload'] as String;
    final String signature = await currentIdentity.signPayload(payload);
    final AccountSession rotated = await _api.refreshAccount(
      refreshToken: session.refreshToken,
      challengeId: challenge['challenge_id'] as String,
      payload: payload,
      signature: signature,
    );
    accountSession = rotated;
    latestPolicy = rotated.policy;
    await _store.saveAccountSession(rotated);
    return rotated;
  }

  String _describeApprovalRequest(Map<String, dynamic> request) {
    final Map<String, dynamic> from = request['requesting_installation'] is Map
        ? Map<String, dynamic>.from(request['requesting_installation'] as Map)
        : <String, dynamic>{};
    return '${request['request_id']}: ${from['platform']}, first seen '
        '${from['first_seen_at']}, joined by ${from['registration_method']}'
        '${approvalReasonLines(request).map((String l) => '\n  $l').join()}';
  }

  Future<void> approveRequest(String requestId) {
    limitedSessionResult = null;
    return _run('Approving with step-up…', () async {
      final InstallationIdentity? currentIdentity = identity;
      final StepUpKeyMetadata? key = stepUpKey;
      if (accountSession == null || currentIdentity == null) {
        throw ApiException('Log in first.');
      }
      if (!openApprovalRequests.any(
        (Map<String, dynamic> r) => r['request_id'] == requestId,
      )) {
        await _reloadApprovalRequests(currentIdentity);
        _recordLimited(<String>[
          'NOT OPEN: that request lapsed, was replaced or was answered; '
              'nothing was signed. The list is current again.',
        ]);
        return;
      }
      final bool withKey = key != null && stepUpUsable;
      if (!withKey && _appPinOrNull == null) {
        throw ApiException(
          'Approving needs this phone\'s bound step-up key or the app PIN: '
          '${stepUpUnavailable ?? 're-enrol the key, or type the PIN'}',
        );
      }
      // The approver must itself be clean: a fresh scan first.
      final String deviceProofToken = await _freshDeviceToken();
      deviceToken = deviceProofToken;
      await _collectIntegrityWithToken(deviceProofToken, currentIdentity);
      try {
        await _withAccessToken(
          (String accessToken) => _api.approveUpgrade(
            accessToken: accessToken,
            signingIdentity: currentIdentity,
            requestId: requestId,
            stepUpFactor: withKey ? key.factor : null,
            signStepUp: withKey
                ? (String payload) => _stepUpKeyProvider.sign(
                      payload,
                      reason: 'Approve a sign-in on another phone',
                    )
                : null,
            appPin: _appPinOrNull,
          ),
        );
        await _reloadApprovalRequests(currentIdentity);
        _recordLimited(<String>[
          'PASS: request approved',
          'POST /v1/auth/approvals/$requestId/approve: 200',
        ]);
      } on NativeKeyException catch (error) {
        _recordLimited(<String>[
          error.code == 'STEPUP_CANCELLED'
              ? 'CANCELLED: no step-up signature was produced; nothing was sent'
              : 'FAIL: the step-up key could not sign',
          '${error.message} [${error.code}]',
        ]);
      } on ApiException catch (error) {
        _noteStepUpRefusal(error);
        await _reloadApprovalRequests(currentIdentity);
        _recordLimited(<String>[
          'NOT APPROVED: ${error.code}',
          if (error.code == 'stepup_key_other_account')
            "Re-enrol the step-up key with this account's password "
                '(Step-up section), then approve again.',
          if (error.code == 'approval_superseded')
            'The same phone asked again; approve its newer request.',
          'POST /v1/auth/approvals/$requestId/approve: '
              '${error.statusCode} ${error.code}',
        ]);
      }
    });
  }

  Future<void> denyRequest(String requestId) {
    limitedSessionResult = null;
    return _run('Denying the request…', () async {
      final InstallationIdentity? currentIdentity = identity;
      if (accountSession == null || currentIdentity == null) {
        throw ApiException('Log in first.');
      }
      try {
        await _withAccessToken(
          (String accessToken) => _api.denyUpgrade(
            accessToken: accessToken,
            signingIdentity: currentIdentity,
            requestId: requestId,
          ),
        );
        await _reloadApprovalRequests(currentIdentity);
        _recordLimited(<String>[
          'Request denied',
          'POST /v1/auth/approvals/$requestId/deny: 200',
        ]);
      } on ApiException catch (error) {
        await _reloadApprovalRequests(currentIdentity);
        _recordLimited(<String>[
          'NOT DENIED: ${error.code}',
          'POST /v1/auth/approvals/$requestId/deny: '
              '${error.statusCode} ${error.code}',
        ]);
      }
    });
  }

  /// Signs out on the server first, then drops the tokens on this phone.
  /// Dropping them locally alone left a copied token, used with this phone's
  /// key, valid until it expired (review R6, DESIGN.md 76). A server that
  /// already does not know the session is fine; one that cannot be reached
  /// is reported, and the tokens are dropped here anyway.
  Future<void> clearAccountSession() {
    return _run('Signing out…', () async {
      final InstallationIdentity? currentIdentity = identity;
      String outcome = 'Signed out';
      if (accountSession != null && currentIdentity != null) {
        try {
          await _withAccessToken(
            (String accessToken) => _api.logout(
              accessToken: accessToken,
              signingIdentity: currentIdentity,
            ),
          );
        } on ApiException catch (error) {
          if (error.statusCode != 401) {
            outcome = 'Signed out on this phone; the server answered '
                '${error.code ?? error.statusCode}';
          }
        } catch (error) {
          outcome = 'Signed out on this phone; the server could not be '
              'reached: $error';
        }
      }
      await _store.clearAccountSession();
      accountSession = null;
      latestPolicy = summary?.policy;
      status = outcome;
      debugPrint('SESSION: sign-out: $outcome');
    });
  }

  Future<void> simulateFreshInstallation() {
    return _run('Generating a new installation identity…', () async {
      await _store.clearLocalInstallation();
      identity = await _store.loadOrCreateIdentity();
      registration = null;
      summary = null;
      accountSession = null;
      latestPolicy = null;
      deviceToken = null;
      reinstallHint = await _hintReader.read();
      await _registerAndProve();
      status = 'New installation registered; inspect the recognition method';
    });
  }

  @override
  void dispose() {
    _api.close();
    super.dispose();
  }
}

class DeviceRecognitionPage extends StatefulWidget {
  const DeviceRecognitionPage({super.key});

  @override
  State<DeviceRecognitionPage> createState() => _DeviceRecognitionPageState();
}

class _DeviceRecognitionPageState extends State<DeviceRecognitionPage> {
  late final DeviceRecognitionController _controller;
  final TextEditingController _handleController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _stolenRefreshController =
      TextEditingController(text: injectedStolenRefreshToken);
  /// Owner request (2026-10-12): a mistyped test password is otherwise
  /// invisible; both password fields can be shown while typing.
  bool _showPasswords = false;

  Widget _showPasswordToggle() {
    return IconButton(
      tooltip: _showPasswords ? 'Hide password' : 'Show password',
      icon: Icon(_showPasswords ? Icons.visibility_off : Icons.visibility),
      onPressed: () => setState(() => _showPasswords = !_showPasswords),
    );
  }

  final TextEditingController _stepUpPasswordController =
      TextEditingController();
  final TextEditingController _appPinController = TextEditingController();
  final TextEditingController _appPinPasswordController =
      TextEditingController();
  // The app PIN section is protected while either of its fields has focus,
  // that is while its keyboard is up (DESIGN.md 82).
  final FocusNode _appPinFocus = FocusNode();
  final FocusNode _appPinPasswordFocus = FocusNode();
  bool _pinScreenProtected = false;

  void _onPinFocusChanged() {
    final bool protect = _appPinFocus.hasFocus || _appPinPasswordFocus.hasFocus;
    if (protect == _pinScreenProtected) {
      return;
    }
    _pinScreenProtected = protect;
    unawaited(
      SecureScreen.protect(protect).then((Map<String, dynamic> applied) {
        debugPrint('SECURE_SCREEN: protect=$protect applied=$applied');
      }),
    );
  }
  final TextEditingController _stolenAccessController =
      TextEditingController(text: injectedStolenAccessToken);

  @override
  void initState() {
    super.initState();
    _controller = DeviceRecognitionController()..addListener(_onChanged);
    unawaited(_controller.bootstrap());
    _appPinFocus.addListener(_onPinFocusChanged);
    _appPinPasswordFocus.addListener(_onPinFocusChanged);
  }

  void _onChanged() {
    if (!mounted) {
      return;
    }
    setState(() {});
    final String? error = _controller.lastError;
    if (error != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) {
          return;
        }
        ScaffoldMessenger.of(context)
          ..hideCurrentSnackBar()
          ..showSnackBar(SnackBar(content: Text(error)));
      });
    }
  }

  @override
  void dispose() {
    _controller
      ..removeListener(_onChanged)
      ..dispose();
    _handleController.dispose();
    _passwordController.dispose();
    _stolenRefreshController.dispose();
    _stolenAccessController.dispose();
    _stepUpPasswordController.dispose();
    _appPinController.dispose();
    _appPinPasswordController.dispose();
    _appPinFocus.dispose();
    _appPinPasswordFocus.dispose();
    if (_pinScreenProtected) {
      unawaited(SecureScreen.protect(false));
    }
    super.dispose();
  }

  Widget _field(String label, String? value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          SizedBox(
            width: 150,
            child: Text(
              label,
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
          ),
          Expanded(
            child: SelectableText(value?.isNotEmpty == true ? value! : '—'),
          ),
        ],
      ),
    );
  }

  Widget _testResultPanel(String title, String result) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        border: Border.all(color: Theme.of(context).dividerColor),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            title,
            style: const TextStyle(fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 8),
          SelectableText(result),
        ],
      ),
    );
  }

  Widget _identityCard() {
    final InstallationIdentity? identity = _controller.identity;
    final RegistrationState? registration = _controller.registration;
    final DeviceSummary? summary = _controller.summary;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(
              'Installation and device record',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 12),
            _field('Installation ID', identity?.installationId),
            _field('Server device ID', summary?.deviceId ?? registration?.deviceId),
            _field('Key thumbprint',
                summary?.keyThumbprint ?? identity?.keyThumbprint),
            _field('Key algorithm', summary?.keyAlgorithm ?? identity?.algorithm),
            _field('Native key alias', identity?.keyAlias),
            _field('Native key provider', identity?.provider),
            _field('Native security level', identity?.securityLevel),
            _field(
              'Key created this launch',
              identity == null ? null : (identity.createdThisLaunch ? 'Yes' : 'No'),
            ),
            _field(
              'Hardware-backed locally',
              identity == null ? null : (identity.hardwareBacked ? 'Yes' : 'No'),
            ),
            _field(
              'Private key exportable',
              identity == null
                  ? null
                  : (identity.privateKeyExportable ? 'Yes' : 'No'),
            ),
            _field('Signature encoding', identity?.signatureFormat),
            _field('Remote key attestation', 'Not used'),
            _field('Current recognition',
                registration?.method ?? summary?.method),
            _field('Current confidence',
                registration?.confidence ?? summary?.confidence),
            _field('Enrollment origin', summary?.method),
            _field('Platform', summary?.platform),
            _field('Server device status', summary?.deviceStatus),
            _field('Known installations', summary?.installationCount.toString()),
            _field('Linked accounts', summary?.linkedAccountCount.toString()),
            _field('Last seen', summary?.lastSeenAt),
            _field(
              'Reinstall hint available',
              _controller.reinstallHint == null
                  ? 'No'
                  : 'Yes (${_controller.reinstallHint!.kind})',
            ),
          ],
        ),
      ),
    );
  }

  Widget _integrityCard() {
    final IntegrityDecision? integrity = _controller.latestIntegrity;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(
              'Native device/app integrity',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            const Text(
              'The server chooses native probes, the device collects measurements, '
              'the non-exportable installation key signs the complete report, and '
              'only the server calculates the score. No Google Play Integrity, '
              'SafetyNet, Apple App Attest, or DeviceCheck service is used.',
            ),
            const SizedBox(height: 12),
            if (integrity == null)
              const Text('No native integrity report has been accepted yet.')
            else ...<Widget>[
              _field('Integrity mode', integrity.mode),
              _field('Server score', '${integrity.score}/100'),
              _field('Server verdict', integrity.verdict),
              _field('Hard block signal', integrity.hardBlock ? 'Yes' : 'No'),
              _field('Report ID', integrity.reportId),
              _field('Report time', integrity.createdAt),
              _field(
                'Freshness window',
                '${integrity.freshForSeconds} seconds',
              ),
              _field('Remote attestation', integrity.remoteAttestation),
              _field(
                'Server-requested probes',
                _controller.lastIntegrityProbes.isEmpty
                    ? null
                    : _controller.lastIntegrityProbes.join(', '),
              ),
              _field(
                'Debug test fixture',
                _controller.lastIntegrityTestFixture,
              ),
              const SizedBox(height: 8),
              const Text(
                'Integrity reasons',
                style: TextStyle(fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 6),
              if (integrity.reasons.isEmpty)
                const Text('No integrity-risk signals were scored.')
              else
                for (final IntegrityRiskReason reason in integrity.reasons)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Text(
                      '${reason.code} (+${reason.points})'
                      '${reason.hard ? ' [HARD]' : ''}: ${reason.message}',
                    ),
                  ),
            ],
            const SizedBox(height: 12),
            FilledButton.tonalIcon(
              onPressed:
                  _controller.busy ? null : _controller.runIntegrityScan,
              icon: const Icon(Icons.security),
              label: const Text('Run native integrity scan'),
            ),
            if (measureLocation || measureMockLocation) ...<Widget>[
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: _controller.busy ? null : _controller.allowLocation,
                icon: const Icon(Icons.location_on_outlined),
                label: Text(
                  _controller.locationPermission == null
                      ? 'Allow location (location measurements)'
                      : 'Location permission: ${_controller.locationPermission}',
                ),
              ),
            ],
            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 8),
            const Text(
              'Controlled Android compromise tests',
              style: TextStyle(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            const Text(
              'DEBUG APK ONLY. These buttons inject deterministic native measurements '
              'into the same signed integrity report so the server scoring and gate can '
              'be tested without rooting this known-good phone. Release APKs reject the fixtures.',
            ),
            const SizedBox(height: 10),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: <Widget>[
                OutlinedButton(
                  onPressed: _controller.busy
                      ? null
                      : _controller.testFridaRuntimeDetection,
                  child: const Text('1. Frida runtime'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy
                      ? null
                      : _controller.testFridaPortDetection,
                  child: const Text('2. Frida port'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy
                      ? null
                      : _controller.testHookFrameworkDetection,
                  child: const Text('3. Hook framework'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy
                      ? null
                      : _controller.testRootSuDetection,
                  child: const Text('4. Root + su'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy
                      ? null
                      : _controller.testWritableMountDetection,
                  child: const Text('5. Writable mount'),
                ),
                FilledButton.tonal(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testIntegrityEnforcement,
                  child: const Text('6. Enforce rejection'),
                ),
              ],
            ),
            if (_controller.integrityAttackTestResult != null) ...<Widget>[
              const SizedBox(height: 10),
              SelectableText(
                _controller.integrityAttackTestResult!,
                style: const TextStyle(fontFamily: 'monospace'),
              ),
            ],
            const SizedBox(height: 8),
            const Text(
              'Boundary: on a fully compromised OS these local measurements can '
              'still be falsified. The server therefore combines them with '
              'cryptographic key possession, request proof, replay prevention, '
              'and server-observed account/device behavior.',
            ),
          ],
        ),
      ),
    );
  }

  Widget _riskPolicyCard() {
    final RiskPolicyDecision? policy =
        _controller.latestPolicy ?? _controller.summary?.policy;
    final bool hasAccount = _controller.accountSession != null;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(
              'Device/account risk policy',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            const Text(
              'The policy uses only server-side device/install/account relationships. '
              'It does not add hardware fingerprint attributes or PII. Keep the server '
              'in observe mode while tuning the thresholds.',
            ),
            const SizedBox(height: 12),
            if (policy == null)
              const Text('No policy decision has been returned yet.')
            else ...<Widget>[
              _field('Policy mode', policy.mode),
              _field('Event', policy.eventType),
              _field('Risk score', policy.score.toString()),
              _field('Recommended action', policy.recommendedAction),
              _field('Effective action', policy.effectiveAction),
              _field('Enforced', policy.enforced ? 'Yes' : 'No'),
              _field('Decision ID', policy.decisionId),
              _field('Decision time', policy.createdAt),
              const SizedBox(height: 8),
              const Text(
                'Reasons',
                style: TextStyle(fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 6),
              if (policy.reasons.isEmpty)
                const Text('No elevated-risk reasons.')
              else
                for (final RiskPolicyReason reason in policy.reasons)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Text(
                      '${reason.code} (+${reason.points}): ${reason.message}',
                    ),
                  ),
              const Divider(height: 24),
              _field(
                'Device accounts',
                policy.context['device_account_count']?.toString(),
              ),
              _field(
                'Projected device accounts',
                policy.context['projected_device_account_count']?.toString(),
              ),
              _field(
                'Account devices',
                policy.context['account_device_count']?.toString(),
              ),
              _field(
                'Projected account devices',
                policy.context['projected_account_device_count']?.toString(),
              ),
              _field(
                'Recent reinstalls',
                policy.context['recent_reinstall_count']?.toString(),
              ),
              _field(
                'Reinstall window (hours)',
                policy.context['reinstall_window_hours']?.toString(),
              ),
              _field(
                'Registration method',
                policy.context['registration_method']?.toString(),
              ),
              _field(
                'Installation status',
                policy.context['installation_status']?.toString(),
              ),
              _field(
                'Device status',
                policy.context['device_status']?.toString(),
              ),
              _field(
                'Thresholds',
                "step_up=${policy.thresholds['step_up']}, "
                    "review=${policy.thresholds['review']}, "
                    "block=${policy.thresholds['block']}",
              ),
            ],
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _controller.busy || !hasAccount
                  ? null
                  : _controller.refreshPolicy,
              icon: const Icon(Icons.policy_outlined),
              label: const Text('Evaluate current account risk'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _accountCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(
              'Cross-account recognition test',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            const Text(
              'Use a non-PII test handle. The server stores a keyed lookup '
              'digest rather than the clear-text handle.',
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _handleController,
              enabled: !_controller.busy,
              decoration: const InputDecoration(
                labelText: 'Test account handle',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _passwordController,
              enabled: !_controller.busy,
              obscureText: !_showPasswords,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: 'Password (10–72 UTF-8 bytes)',
                border: const OutlineInputBorder(),
                suffixIcon: _showPasswordToggle(),
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: <Widget>[
                FilledButton(
                  onPressed: _controller.busy
                      ? null
                      : () => _controller.createAccount(
                            _handleController.text,
                            _passwordController.text,
                          ),
                  child: const Text('Create account'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy
                      ? null
                      : () => _controller.loginAccount(
                            _handleController.text,
                            _passwordController.text,
                          ),
                  child: const Text('Log in'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testBoundRefresh,
                  child: const Text('Test bound refresh'),
                ),
                TextButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.clearAccountSession,
                  child: const Text('Sign out'),
                ),
              ],
            ),
            const Divider(height: 32),
            Text(
              'Controlled stolen-refresh-token test',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'TEST BUILDS ONLY. On Phone A, copy its fresh refresh token. '
              'On Phone B, paste/inject that token here and attempt refresh. '
              'Phone B signs the server challenge with Phone B\'s native key; '
              'the server should reject it because the token is bound to Phone A.',
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _stolenRefreshController,
              enabled: !_controller.busy,
              minLines: 2,
              maxLines: 4,
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                labelText: 'Refresh token stolen from Phone A',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: <Widget>[
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.copyRefreshTokenForAttackTest,
                  child: const Text('Copy my refresh token (test only)'),
                ),
                FilledButton.tonal(
                  onPressed: _controller.busy ||
                          _stolenRefreshController.text.trim().isEmpty
                      ? null
                      : () => _controller.testStolenRefreshToken(
                            _stolenRefreshController.text,
                          ),
                  child: const Text('Attempt stolen refresh'),
                ),
              ],
            ),
            if (_controller.boundRefreshTestResult != null) ...<Widget>[
              const SizedBox(height: 16),
              _testResultPanel(
                'Legitimate bound-refresh result',
                _controller.boundRefreshTestResult!,
              ),
            ],
            if (_controller.stolenRefreshTestResult != null) ...<Widget>[
              const SizedBox(height: 12),
              _testResultPanel(
                'Stolen refresh attack result',
                _controller.stolenRefreshTestResult!,
              ),
            ],
            const Divider(height: 36),
            Text(
              'Access-token proof-of-possession',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'Every protected API request now signs a fresh proof containing '
              'the access-token hash, HTTP method, path, request-body hash, '
              'timestamp, and one-time nonce. The server verifies the signature '
              'with the installation public key and consumes the nonce to stop replay.',
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: <Widget>[
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testBoundAccessProof,
                  child: const Text('Test protected access'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.copyAccessTokenForAttackTest,
                  child: const Text('Copy my access token (test only)'),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Text(
              'Controlled stolen-access-token test',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'On Phone A, copy a fresh access token. On Phone B, paste or '
              'inject it below. Phone B builds a structurally correct proof for '
              "Phone A's token but signs it with Phone B's native key. The "
              'protected request must fail at signature verification.',
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _stolenAccessController,
              enabled: !_controller.busy,
              minLines: 2,
              maxLines: 4,
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                labelText: 'Access token stolen from Phone A',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            FilledButton.tonal(
              onPressed: _controller.busy ||
                      _stolenAccessController.text.trim().isEmpty
                  ? null
                  : () => _controller.testStolenAccessToken(
                        _stolenAccessController.text,
                      ),
              child: const Text('Attempt stolen protected request'),
            ),
            if (_controller.boundAccessTestResult != null) ...<Widget>[
              const SizedBox(height: 16),
              _testResultPanel(
                'Legitimate protected-access result',
                _controller.boundAccessTestResult!,
              ),
            ],
            if (_controller.stolenAccessTestResult != null) ...<Widget>[
              const SizedBox(height: 12),
              _testResultPanel(
                'Stolen access-token attack result',
                _controller.stolenAccessTestResult!,
              ),
            ],
            const Divider(height: 36),
            Text(
              'Step-up for sensitive operations',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'A second, optional key that cannot sign without the device '
              'passcode. A gated operation needs its signature over this '
              "request's nonce, so a hijacked app process cannot approve it "
              'silently.',
            ),
            const SizedBox(height: 8),
            Text(_controller.stepUpStatusLine),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: <Widget>[
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testSensitiveWithoutStepUp,
                  child: const Text('Sensitive op without step-up'),
                ),
                FilledButton.tonal(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null ||
                          !_controller.stepUpUsable
                      ? null
                      : _controller.testSensitiveWithStepUp,
                  child: const Text('Sensitive op with step-up'),
                ),
              ],
            ),
            if (_controller.accountSession != null) ...<Widget>[
              const SizedBox(height: 12),
              const Text(
                'App PIN, checked by the server (DESIGN.md 78). Sent with '
                'every step-up while filled; the DBA decides where it is '
                'needed.',
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _appPinController,
                focusNode: _appPinFocus,
                enabled: !_controller.busy,
                obscureText: !_showPasswords,
                keyboardType: TextInputType.number,
                autocorrect: false,
                enableSuggestions: false,
                // No keyboard may learn the PIN (DESIGN.md 82).
                enableIMEPersonalizedLearning: false,
                onChanged: _controller.updateAppPinEntry,
                decoration: InputDecoration(
                  labelText: 'App PIN',
                  border: const OutlineInputBorder(),
                  suffixIcon: _showPasswordToggle(),
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _appPinPasswordController,
                focusNode: _appPinPasswordFocus,
                enabled: !_controller.busy,
                obscureText: !_showPasswords,
                autocorrect: false,
                enableSuggestions: false,
                enableIMEPersonalizedLearning: false,
                onChanged: (_) => setState(() {}),
                decoration: InputDecoration(
                  labelText: 'Account password (to set the app PIN)',
                  border: const OutlineInputBorder(),
                  suffixIcon: _showPasswordToggle(),
                ),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: <Widget>[
                  FilledButton(
                    onPressed: _controller.busy ||
                            _appPinPasswordController.text.isEmpty ||
                            _controller.appPinEntry.isEmpty
                        ? null
                        : () => _controller.setAppPin(
                              _appPinPasswordController.text,
                            ),
                    child: const Text('Set app PIN'),
                  ),
                  FilledButton.tonal(
                    onPressed: _controller.busy ||
                            _controller.appPinEntry.isEmpty
                        ? null
                        : _controller.testSensitiveWithAppPin,
                    child: const Text('Sensitive op with app PIN'),
                  ),
                ],
              ),
            ],
            if (_controller.accountSession != null &&
                !_controller.stepUpUsable) ...<Widget>[
              const SizedBox(height: 12),
              TextField(
                controller: _stepUpPasswordController,
                enabled: !_controller.busy,
                obscureText: !_showPasswords,
                autocorrect: false,
                enableSuggestions: false,
                onChanged: (_) => setState(() {}),
                decoration: InputDecoration(
                  labelText: 'Account password (to re-enrol step-up)',
                  border: const OutlineInputBorder(),
                  suffixIcon: _showPasswordToggle(),
                ),
              ),
              const SizedBox(height: 8),
              FilledButton(
                onPressed: _controller.busy ||
                        _stepUpPasswordController.text.isEmpty
                    ? null
                    : () => _controller.reenrolStepUpKey(
                          _stepUpPasswordController.text,
                        ),
                child: const Text('Re-enrol step-up key'),
              ),
            ],
            if (_controller.stepUpTestResult != null) ...<Widget>[
              const SizedBox(height: 12),
              _testResultPanel(
                'Step-up result',
                _controller.stepUpTestResult!,
              ),
            ],
            const Divider(height: 36),
            Text(
              'Access-proof boundary tests (1-4)',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'These deliberately reuse or alter a signed request after the native '
              'key has signed it. Each test must be rejected for the specific '
              'reason shown below.',
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: <Widget>[
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testAccessProofReplay,
                  child: const Text('1. Test replay'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testAccessProofBodyTampering,
                  child: const Text('2. Test body tampering'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testAccessProofPathAndMethodTampering,
                  child: const Text('3. Test path + method'),
                ),
                OutlinedButton(
                  onPressed: _controller.busy ||
                          _controller.accountSession == null
                      ? null
                      : _controller.testExpiredAccessProofTimestamp,
                  child: const Text('4. Test stale timestamp'),
                ),
              ],
            ),
            if (_controller.replayAttackTestResult != null) ...<Widget>[
              const SizedBox(height: 16),
              _testResultPanel(
                '1. Replay result',
                _controller.replayAttackTestResult!,
              ),
            ],
            if (_controller.bodyTamperTestResult != null) ...<Widget>[
              const SizedBox(height: 12),
              _testResultPanel(
                '2. Body-tampering result',
                _controller.bodyTamperTestResult!,
              ),
            ],
            if (_controller.pathMethodTamperTestResult != null) ...<Widget>[
              const SizedBox(height: 12),
              _testResultPanel(
                '3. Path/method result',
                _controller.pathMethodTamperTestResult!,
              ),
            ],
            if (_controller.timestampExpiryTestResult != null) ...<Widget>[
              const SizedBox(height: 12),
              _testResultPanel(
                '4. Timestamp-window result',
                _controller.timestampExpiryTestResult!,
              ),
            ],
            const SizedBox(height: 16),
            _field('Current account ID', _controller.accountSession?.accountId),
            _field(
              'Refresh session present',
              _controller.accountSession == null ? 'No' : 'Yes',
            ),
          ],
        ),
      ),
    );
  }

  Widget _limitedSessionCard() {
    final bool signedIn = _controller.accountSession != null;
    final bool busy = _controller.busy;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(
              'Limited session and upgrade',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            const Text(
              'In enforce mode, soft risk at sign-in gives a limited session '
              'instead of a refusal. It upgrades by itself once the cause '
              'clears, or with a proof: a step-up on this phone (if the DBA '
              'allows it) or an approval from another phone of the account.',
            ),
            const SizedBox(height: 8),
            Text(_controller.sessionScopeLine),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: <Widget>[
                OutlinedButton(
                  onPressed:
                      busy || !signedIn ? null : _controller.upgradeByRecheck,
                  child: const Text('Upgrade after a clean scan'),
                ),
                FilledButton.tonal(
                  onPressed: busy || !signedIn || !_controller.stepUpUsable
                      ? null
                      : _controller.upgradeWithStepUp,
                  child: const Text('Upgrade with step-up on this phone'),
                ),
                OutlinedButton(
                  onPressed: busy || !signedIn || _controller.waitingForApproval
                      ? null
                      : _controller.requestApproval,
                  child: const Text('Ask another phone to approve'),
                ),
              ],
            ),
            if (_controller.waitingForApproval) ...<Widget>[
              const SizedBox(height: 12),
              Row(
                children: <Widget>[
                  const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text(
                      'Waiting for your other phone to approve. This phone '
                      'checks every 5 seconds and finishes by itself.',
                    ),
                  ),
                  TextButton(
                    onPressed: _controller.stopWaitingForApproval,
                    child: const Text('Stop'),
                  ),
                ],
              ),
            ],
            const Divider(height: 32),
            Text(
              'Approve another phone',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'On a phone with a full session for the same account: list the '
              'requests, check where each comes from, and approve with your '
              'screen lock - or deny it if you did not just sign in.',
            ),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed:
                  busy || !signedIn ? null : _controller.loadApprovalRequests,
              child: const Text('Show approval requests'),
            ),
            for (final Map<String, dynamic> request
                in _controller.openApprovalRequests) ...<Widget>[
              const SizedBox(height: 12),
              Text(_requestLabel(request)),
              const SizedBox(height: 6),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: <Widget>[
                  FilledButton.tonal(
                    onPressed: busy || !_controller.stepUpUsable
                        ? null
                        : () => _controller.approveRequest(
                              request['request_id'] as String,
                            ),
                    child: const Text('Approve (screen lock)'),
                  ),
                  TextButton(
                    onPressed: busy
                        ? null
                        : () => _controller.denyRequest(
                              request['request_id'] as String,
                            ),
                    child: const Text('Deny'),
                  ),
                ],
              ),
            ],
            if (_controller.limitedSessionResult != null) ...<Widget>[
              const SizedBox(height: 12),
              _testResultPanel(
                'Limited session result',
                _controller.limitedSessionResult!,
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _requestLabel(Map<String, dynamic> request) {
    final Map<String, dynamic> from = request['requesting_installation'] is Map
        ? Map<String, dynamic>.from(request['requesting_installation'] as Map)
        : <String, dynamic>{};
    final String id = request['request_id'] as String? ?? '';
    final List<String> reasons = _controller.approvalReasonLines(request);
    return <String>[
      'Request ${id.length > 8 ? id.substring(0, 8) : id}: '
          '${from['platform']} phone first seen ${from['first_seen_at']}, '
          'joined by ${from['registration_method']}',
      if (reasons.isNotEmpty) 'Approving accepts:',
      ...reasons,
    ].join('\n');
  }

  Widget _explanationCard() {
    return const Card(
      child: Padding(
        padding: EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(
              'What the result means',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.w600),
            ),
            SizedBox(height: 8),
            Text(
              'exact_key / high: the app proved possession of the same local '
              'private key. reinstall_hint / medium: a newly generated key was '
              'correlated using Android ID or IDFV. That hint is never accepted '
              'as authentication. new_device / new: neither signal matched.',
            ),
            SizedBox(height: 8),
            Text(
              'The private P-256 key is created and used by Android Keystore '
              'or the iOS Security framework. It is never returned to Dart. '
              'Android prefers StrongBox and otherwise uses Android Keystore; '
              'iOS requires Secure Enclave on physical hardware and uses a '
              'simulator-only Keychain fallback that is explicitly marked as '
              'not hardware-backed.',
            ),
            SizedBox(height: 8),
            Text(
              'Hardware protection shown here is reported by the local OS. The '
              'server verifies key possession but does not remotely attest the '
              'hardware because Google Play Integrity and Apple App Attest are '
              'intentionally not used in this prototype.',
            ),
            SizedBox(height: 8),
            Text(
              'Device/account bearer tokens are now sender-constrained for '
              'ordinary protected API calls. Each request carries a signed '
              'token hash, method, path, body hash, timestamp and one-time '
              'nonce. Refresh tokens continue to use the separate server '
              'challenge and rotation flow.',
            ),
            SizedBox(height: 8),
            Text(
              'Native integrity measurement is challenge-driven and server scored. '
              'Android probes app signing identity, debugger/tracer state, root '
              'artifacts, Verified Boot-related properties, SELinux/mount state, '
              'runtime maps and Frida ports. iOS probes signing identity, debugger '
              'state, jailbreak paths, sandbox behavior, loaded images and DYLD '
              'injection state. These are defense-in-depth signals rather than '
              'unforgeable remote attestation.',
            ),
            SizedBox(height: 8),
            Text(
              'The policy layer is intentionally separate from cryptographic '
              'identity. The native key proves which installation is calling; '
              'the risk policy then decides how to treat relationships such as '
              'multiple accounts on one device, one account on multiple devices, '
              'and repeated reinstalls. In observe mode these are recommendations '
              'only. Revoked installations/devices are always rejected.',
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final bool insecureTransport = apiBaseUrl.startsWith('http://');
    return Scaffold(
      appBar: AppBar(title: const Text('Device Recognition Lab')),
      body: SafeArea(
        child: SelectionArea(
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: <Widget>[
              if (insecureTransport)
                Card(
                  color: Theme.of(context).colorScheme.errorContainer,
                  child: const Padding(
                    padding: EdgeInsets.all(12),
                    child: Text(
                      'The configured API URL uses HTTP. Use only synthetic test '
                      'accounts until the laptop is behind HTTPS.',
                    ),
                  ),
                ),
              Card(
                child: ListTile(
                  leading: _controller.busy
                      ? const SizedBox.square(
                          dimension: 24,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.verified_user_outlined),
                  title: Text(_controller.status),
                  subtitle: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text('API: $apiBaseUrl'),
                      if (_controller.lastError != null) ...<Widget>[
                        const SizedBox(height: 6),
                        Text(
                          _controller.lastError!,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              _identityCard(),
              _integrityCard(),
              _riskPolicyCard(),
              _accountCard(),
              _limitedSessionCard(),
              _explanationCard(),
              const SizedBox(height: 8),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: <Widget>[
                  FilledButton.icon(
                    onPressed:
                        _controller.busy ? null : _controller.reauthenticate,
                    icon: const Icon(Icons.key),
                    label: const Text('Prove installation again'),
                  ),
                  OutlinedButton.icon(
                    onPressed:
                        _controller.busy ? null : _controller.refreshSummary,
                    icon: const Icon(Icons.refresh),
                    label: const Text('Refresh device record'),
                  ),
                  OutlinedButton.icon(
                    onPressed: _controller.busy
                        ? null
                        : () async {
                            final bool? accepted = await showDialog<bool>(
                              context: context,
                              builder: (BuildContext dialogContext) {
                                return AlertDialog(
                                  title: const Text(
                                    'Simulate a fresh installation?',
                                  ),
                                  content: const Text(
                                    'This deletes the native platform key, IDs, and '
                                    'tokens, then generates a new key. The OS reinstall '
                                    'hint remains, allowing you to test server '
                                    'correlation. It is not an exact simulation '
                                    'of every iOS uninstall behavior.',
                                  ),
                                  actions: <Widget>[
                                    TextButton(
                                      onPressed: () =>
                                          Navigator.pop(dialogContext, false),
                                      child: const Text('Cancel'),
                                    ),
                                    FilledButton(
                                      onPressed: () =>
                                          Navigator.pop(dialogContext, true),
                                      child: const Text('Continue'),
                                    ),
                                  ],
                                );
                              },
                            );
                            if (accepted == true) {
                              await _controller.simulateFreshInstallation();
                            }
                          },
                    icon: const Icon(Icons.restart_alt),
                    label: const Text('Simulate fresh installation'),
                  ),
                ],
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }
}
