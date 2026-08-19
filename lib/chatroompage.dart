// This file keeps the old filename so the project needs the smallest possible
// structural change. The chat room has intentionally been replaced by a
// device-recognition laboratory.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

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
  }) async {
    final Uri uri = Uri.parse('$_base$path');
    final Map<String, String> headers = <String, String>{
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      if (bearerToken != null) 'Authorization': 'Bearer $bearerToken',
    };

    late final http.Response response;
    try {
      if (method == 'GET') {
        response = await _client
            .get(uri, headers: headers)
            .timeout(_networkTimeout);
      } else {
        response = await _client
            .post(
              uri,
              headers: headers,
              body: jsonEncode(body ?? <String, dynamic>{}),
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

  Future<DeviceSummary> deviceSummary(String token) async {
    final Map<String, dynamic> value = await _request(
      'GET',
      '/v1/device/me',
      bearerToken: token,
    );
    return DeviceSummary.fromJson(value);
  }

  Future<AccountSession> registerAccount({
    required String deviceToken,
    required String handle,
    required String password,
  }) async {
    final Map<String, dynamic> value = await _request(
      'POST',
      '/v1/accounts/register',
      bearerToken: deviceToken,
      body: <String, dynamic>{
        'handle': handle,
        'password': password,
      },
    );
    return AccountSession.fromApi(value);
  }

  Future<AccountSession> loginAccount({
    required String deviceToken,
    required String handle,
    required String password,
  }) async {
    final Map<String, dynamic> value = await _request(
      'POST',
      '/v1/accounts/login',
      bearerToken: deviceToken,
      body: <String, dynamic>{
        'handle': handle,
        'password': password,
      },
    );
    return AccountSession.fromApi(value);
  }

  Future<Map<String, dynamic>> accountMe(String accessToken) {
    return _request(
      'GET',
      '/v1/account/me',
      bearerToken: accessToken,
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
    summary = await _api.deviceSummary(deviceToken!);
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
      summary = await _api.deviceSummary(token);
      status = 'Device record refreshed';
    });
  }

  Future<void> createAccount(String handle, String password) {
    return _run('Creating an account on this device…', () async {
      final String token = await _freshDeviceToken();
      accountSession = await _api.registerAccount(
        deviceToken: token,
        handle: handle,
        password: password,
      );
      await _store.saveAccountSession(accountSession!);
      summary = await _api.deviceSummary(token);
      status = 'Account created and linked to the recognized device';
    });
  }

  Future<void> loginAccount(String handle, String password) {
    return _run('Signing in and linking this device…', () async {
      final String token = await _freshDeviceToken();
      accountSession = await _api.loginAccount(
        deviceToken: token,
        handle: handle,
        password: password,
      );
      await _store.saveAccountSession(accountSession!);
      summary = await _api.deviceSummary(token);
      status = 'Account authenticated on the recognized device';
    });
  }

  Future<void> testBoundRefresh() {
    return _run('Rotating the device-bound refresh token…', () async {
      final AccountSession? session = accountSession;
      final InstallationIdentity? currentIdentity = identity;
      if (session == null || currentIdentity == null) {
        throw ApiException('Create or log in to an account first.');
      }

      final Map<String, dynamic> challenge =
          await _api.refreshChallenge(session.refreshToken);
      final String payload = challenge['payload'] as String;
      final String signature = await currentIdentity.signPayload(payload);
      accountSession = await _api.refreshAccount(
        refreshToken: session.refreshToken,
        challengeId: challenge['challenge_id'] as String,
        payload: payload,
        signature: signature,
      );
      await _store.saveAccountSession(accountSession!);
      await _api.accountMe(accountSession!.accessToken);
      status = 'Refresh token rotated after a valid installation signature';
    });
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
            const SizedBox(height: 12),
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
