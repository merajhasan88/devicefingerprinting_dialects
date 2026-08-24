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

class ApiException implements Exception {
  ApiException(this.message, {this.statusCode, this.code});

  final String message;
  final int? statusCode;
  final String? code;

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

class AccountSession {
  AccountSession({
    required this.accountId,
    required this.accessToken,
    required this.refreshToken,
  });

  final String accountId;
  final String accessToken;
  final String refreshToken;

  factory AccountSession.fromApi(Map<String, dynamic> value) {
    return AccountSession(
      accountId: value['account_id'] as String,
      accessToken: value['access_token'] as String,
      refreshToken: value['refresh_token'] as String,
    );
  }

  factory AccountSession.fromStoredJson(Map<String, dynamic> value) {
    return AccountSession(
      accountId: value['account_id'] as String,
      accessToken: value['access_token'] as String,
      refreshToken: value['refresh_token'] as String,
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'account_id': accountId,
        'access_token': accessToken,
        'refresh_token': refreshToken,
      };
}

class DeviceSummary {
  DeviceSummary({
    required this.installationId,
    required this.deviceId,
    required this.platform,
    required this.keyThumbprint,
    required this.keyAlgorithm,
    required this.method,
    required this.confidence,
    required this.installationCount,
    required this.linkedAccountCount,
    required this.createdAt,
    required this.lastSeenAt,
  });

  final String installationId;
  final String deviceId;
  final String platform;
  final String keyThumbprint;
  final String keyAlgorithm;
  final String method;
  final String confidence;
  final int installationCount;
  final int linkedAccountCount;
  final String createdAt;
  final String lastSeenAt;

  factory DeviceSummary.fromJson(Map<String, dynamic> value) {
    final Map<String, dynamic> recognition =
        Map<String, dynamic>.from(value['recognition'] as Map);
    return DeviceSummary(
      installationId: value['installation_id'] as String,
      deviceId: value['device_id'] as String,
      platform: value['platform'] as String,
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

  Future<Map<String, dynamic>> _protectedRequest(
    String method,
    String path, {
    Map<String, dynamic>? body,
    required String bearerToken,
    required InstallationIdentity signingIdentity,
    String? proofInstallationId,
  }) async {
    final String normalizedMethod = method.toUpperCase();
    final String encodedBody = normalizedMethod == 'GET'
        ? ''
        : jsonEncode(body ?? <String, dynamic>{});
    final String bodyHash =
        crypto.sha256.convert(utf8.encode(encodedBody)).toString();
    final String tokenHash =
        crypto.sha256.convert(utf8.encode(bearerToken)).toString();

    final Map<String, dynamic> proof = <String, dynamic>{
      'access_token_sha256': tokenHash,
      'body_sha256': bodyHash,
      'installation_id': proofInstallationId ?? signingIdentity.installationId,
      'method': normalizedMethod,
      'nonce': _b64UrlNoPadding(_freshNonce()),
      'path': path,
      'timestamp': DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
      'version': 1,
    };

    // The server verifies the exact signed bytes and separately checks every
    // field against the HTTP request that actually arrived.
    final String proofPayload =
        _b64UrlNoPadding(utf8.encode(jsonEncode(proof)));
    final String signature = await signingIdentity.signPayload(proofPayload);

    return _request(
      normalizedMethod,
      path,
      body: body,
      bearerToken: bearerToken,
      encodedBody: normalizedMethod == 'GET' ? null : encodedBody,
      extraHeaders: <String, String>{
        'X-Access-Proof': proofPayload,
        'X-Access-Signature': signature,
      },
    );
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
  })  : _store = store ?? SecureIdentityStore(),
        _hintReader = hintReader ?? ReinstallHintReader(),
        _api = api ?? DeviceApi();

  final SecureIdentityStore _store;
  final ReinstallHintReader _hintReader;
  final DeviceApi _api;

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
    summary = await _api.deviceSummary(deviceToken!, currentIdentity);
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

  Future<void> refreshSummary() {
    return _run('Refreshing the server device record…', () async {
      final String token = await _freshDeviceToken();
      deviceToken = token;
      summary = await _api.deviceSummary(token, identity!);
      status = 'Device record refreshed';
    });
  }

  Future<void> createAccount(String handle, String password) {
    return _run('Creating an account on this device…', () async {
      final String token = await _freshDeviceToken();
      accountSession = await _api.registerAccount(
        deviceToken: token,
        signingIdentity: identity!,
        handle: handle,
        password: password,
      );
      await _store.saveAccountSession(accountSession!);
      summary = await _api.deviceSummary(token, identity!);
      status = 'Account created and linked to the recognized device';
    });
  }

  Future<void> loginAccount(String handle, String password) {
    return _run('Signing in and linking this device…', () async {
      final String token = await _freshDeviceToken();
      accountSession = await _api.loginAccount(
        deviceToken: token,
        signingIdentity: identity!,
        handle: handle,
        password: password,
      );
      await _store.saveAccountSession(accountSession!);
      summary = await _api.deviceSummary(token, identity!);
      status = 'Account authenticated on the recognized device';
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

  Future<void> clearAccountSession() {
    return _run('Clearing local account tokens…', () async {
      await _store.clearAccountSession();
      accountSession = null;
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
