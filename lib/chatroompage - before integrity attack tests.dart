// This file keeps the old filename so the project needs the smallest possible
// structural change. The chat room has intentionally been replaced by a
// device-recognition laboratory.

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

const String apiBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'http://10.0.2.2:5000',
);

const String injectedStolenRefreshToken = String.fromEnvironment(
  'STOLEN_REFRESH_TOKEN',
  defaultValue: '',
);

const String injectedStolenAccessToken = String.fromEnvironment(
  'STOLEN_ACCESS_TOKEN',
  defaultValue: '',
);

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

class NativeIntegrityCollector {
  static const MethodChannel _channel = MethodChannel(
    'devicefingerprinting/integrity_v1',
  );

  Future<Map<String, dynamic>> collect({
    required List<String> requiredProbes,
    required String challengeNonce,
  }) async {
    try {
      final Map<String, dynamic>? value =
          await _channel.invokeMapMethod<String, dynamic>(
        'collect',
        <String, dynamic>{
          'required_probes': requiredProbes,
          'challenge_nonce': challengeNonce,
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
  });

  final String installationId;
  final String deviceId;
  final String keyThumbprint;
  final String keyAlgorithm;
  final String method;
  final String confidence;
  final bool isReinstallCorrelation;

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
  });

  final String accountId;
  final String accessToken;
  final String refreshToken;
  final RiskPolicyDecision? policy;

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
    );
  }

  factory AccountSession.fromStoredJson(Map<String, dynamic> value) {
    return AccountSession(
      accountId: value['account_id'] as String,
      accessToken: value['access_token'] as String,
      refreshToken: value['refresh_token'] as String,
      policy: value['policy'] is Map
          ? RiskPolicyDecision.fromJson(
              Map<String, dynamic>.from(value['policy'] as Map),
            )
          : null,
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'account_id': accountId,
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'policy': policy?.toJson(),
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
  SecureIdentityStore({NativeInstallationKey? nativeKey})
      : _nativeKey = nativeKey ?? NativeInstallationKey(),
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
  final FlutterSecureStorage _storage;

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

  String get _base => apiBaseUrl.endsWith('/')
      ? apiBaseUrl.substring(0, apiBaseUrl.length - 1)
      : apiBaseUrl;

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

    final Map<String, dynamic> proof = <String, dynamic>{
      'access_token_sha256': tokenHash,
      'body_sha256': bodyHash,
      'installation_id': proofInstallationId ?? signingIdentity.installationId,
      'method': normalizedMethod,
      'nonce': nonce,
      'path': path,
      'timestamp': timestamp,
      'version': 1,
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
    ReinstallHint? hint,
  ) async {
    final Map<String, dynamic> response = await _request(
      'POST',
      '/v1/installations/register',
      body: <String, dynamic>{
        'installation_id': identity.installationId,
        'platform': Platform.isAndroid ? 'android' : 'ios',
        'public_key': identity.publicKeyJson,
        'reinstall_hint': hint?.toJson(),
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
  })  : _store = store ?? SecureIdentityStore(),
        _hintReader = hintReader ?? ReinstallHintReader(),
        _api = api ?? DeviceApi(),
        _integrityCollector = integrityCollector ?? NativeIntegrityCollector();

  final SecureIdentityStore _store;
  final ReinstallHintReader _hintReader;
  final DeviceApi _api;
  final NativeIntegrityCollector _integrityCollector;

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
      latestPolicy = accountSession?.policy;
      reinstallHint = await _hintReader.read();
      await _registerAndProve();
      status = 'Installation identity verified';
    });
  }

  Future<void> reauthenticate() {
    return _run('Re-registering and proving key possession…', () async {
      identity ??= await _store.loadOrCreateIdentity();
      reinstallHint ??= await _hintReader.read();
      await _registerAndProve();
      status = 'Fresh device proof accepted';
    });
  }

  Future<void> _registerAndProve() async {
    InstallationIdentity currentIdentity = identity!;
    RegistrationState currentRegistration;
    try {
      currentRegistration = await _api.registerInstallation(
        currentIdentity,
        reinstallHint,
      );
    } on ApiException catch (error) {
      if (error.code != 'registration_race_retry') {
        rethrow;
      }
      currentRegistration = await _api.registerInstallation(
        currentIdentity,
        reinstallHint,
      );
    }

    if (currentRegistration.installationId != currentIdentity.installationId) {
      currentIdentity = currentIdentity.withInstallationId(
        currentRegistration.installationId,
      );
      identity = currentIdentity;
      await _store.saveIdentity(currentIdentity);
    }
    registration = currentRegistration;
    await _store.saveRegistration(currentRegistration);

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
    InstallationIdentity currentIdentity,
  ) async {
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

    final Map<String, dynamic> native = await _integrityCollector.collect(
      requiredProbes: requiredProbes,
      challengeNonce: nonce,
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
      accountSession = await _api.registerAccount(
        deviceToken: token,
        signingIdentity: identity!,
        handle: handle,
        password: password,
      );
      await _store.saveAccountSession(accountSession!);
      latestPolicy = accountSession?.policy;
      summary = await _api.deviceSummary(token, identity!);
      status = 'Account created and linked to the recognized device';
    });
  }

  Future<void> loginAccount(String handle, String password) {
    return _run('Signing in and linking this device…', () async {
      final String token = await _freshDeviceToken();
      deviceToken = token;
      await _collectIntegrityWithToken(token, identity!);
      accountSession = await _api.loginAccount(
        deviceToken: token,
        signingIdentity: identity!,
        handle: handle,
        password: password,
      );
      await _store.saveAccountSession(accountSession!);
      latestPolicy = accountSession?.policy;
      summary = await _api.deviceSummary(token, identity!);
      status = 'Account authenticated on the recognized device';
    });
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

  Future<void> clearAccountSession() {
    return _run('Clearing local account tokens…', () async {
      await _store.clearAccountSession();
      accountSession = null;
      latestPolicy = summary?.policy;
      status = 'Local account tokens cleared';
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
  final TextEditingController _stolenAccessController =
      TextEditingController(text: injectedStolenAccessToken);

  @override
  void initState() {
    super.initState();
    _controller = DeviceRecognitionController()..addListener(_onChanged);
    unawaited(_controller.bootstrap());
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
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Password (10–72 UTF-8 bytes)',
                border: OutlineInputBorder(),
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
                  child: const Text('Clear local account tokens'),
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
