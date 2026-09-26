import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  /// Matches the Android host's channel name exactly. The Dart client is
  /// platform-agnostic and talks to this same name on both platforms.
  private static let keyChannelName = "devicefingerprinting/installation_key_v2"
  private static let integrityChannelName = "devicefingerprinting/integrity_v1"
  private static let stepUpChannelName = "devicefingerprinting/stepup_key_v1"

  private var installationKeys: InstallationKeyManager?
  private var integrityProbes: IntegrityProbeManager?
  private var stepUpKeys: StepUpKeyManager?

  /// Keychain and Secure Enclave calls can block, so they run off the platform
  /// thread. FlutterResult must be invoked on the platform thread, hence the
  /// hop back to main. This mirrors runOffMainThread in MainActivity.kt.
  private let worker = DispatchQueue(
    label: "devicefingerprinting.installation-key",
    qos: .userInitiated
  )

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    registerInstallationKeyChannel(with: engineBridge.pluginRegistry)
    registerIntegrityChannel(with: engineBridge.pluginRegistry)
    registerStepUpKeyChannel(with: engineBridge.pluginRegistry)
  }

  private func registerStepUpKeyChannel(with registry: FlutterPluginRegistry) {
    guard let registrar = registry.registrar(forPlugin: "DeviceTrustStepUpKey") else {
      return
    }

    let bundleIdentifier = Bundle.main.bundleIdentifier ?? "com.example.devicefingerprinting"
    let manager = StepUpKeyManager(bundleIdentifier: bundleIdentifier)
    stepUpKeys = manager

    let channel = FlutterMethodChannel(
      name: AppDelegate.stepUpChannelName,
      binaryMessenger: registrar.messenger()
    )

    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      let arguments = call.arguments as? [String: Any] ?? [:]
      switch call.method {
      case "getOrCreateKey":
        guard let factor = arguments["factor"] as? String else {
          result(FlutterError(
            code: "INVALID_ARGUMENT",
            message: "factor must be a string.",
            details: nil
          ))
          return
        }
        self.runOffPlatformThread(result) { try manager.getOrCreateKey(factor: factor) }

      case "sign":
        guard let payload = arguments["payload"] as? String else {
          result(FlutterError(
            code: "INVALID_ARGUMENT",
            message: "payload must be a base64url string.",
            details: nil
          ))
          return
        }
        let reason = arguments["reason"] as? String ?? "Approve this operation"
        // Off the platform thread: the call blocks while the system prompt is up.
        self.runOffPlatformThread(result) { try manager.signPayload(payload, reason: reason) }

      case "deleteKey":
        self.runOffPlatformThread(result) { try manager.deleteKey() }

      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private func registerIntegrityChannel(with registry: FlutterPluginRegistry) {
    guard let registrar = registry.registrar(forPlugin: "DeviceTrustIntegrity") else {
      return
    }

    let collector = IntegrityProbeManager()
    integrityProbes = collector

    let channel = FlutterMethodChannel(
      name: AppDelegate.integrityChannelName,
      binaryMessenger: registrar.messenger()
    )

    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "collect":
        guard
          let arguments = call.arguments as? [String: Any],
          let nonce = arguments["challenge_nonce"] as? String,
          let required = arguments["required_probes"] as? [String]
        else {
          result(FlutterError(
            code: "INVALID_ARGUMENT",
            message: "challenge_nonce must be a string and required_probes a list of strings.",
            details: nil
          ))
          return
        }
        let fixture = arguments["integrity_test_fixture"] as? String
        self.runOffPlatformThread(result) {
          collector.collect(
            requiredProbes: required,
            challengeNonce: nonce,
            testFixture: fixture
          )
        }

      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private func registerInstallationKeyChannel(with registry: FlutterPluginRegistry) {
    guard let registrar = registry.registrar(forPlugin: "DeviceTrustInstallationKey") else {
      return
    }

    let bundleIdentifier = Bundle.main.bundleIdentifier ?? "com.example.devicefingerprinting"
    let manager = InstallationKeyManager(bundleIdentifier: bundleIdentifier)
    installationKeys = manager

    let channel = FlutterMethodChannel(
      name: AppDelegate.keyChannelName,
      binaryMessenger: registrar.messenger()
    )

    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "getOrCreateKey":
        self.runOffPlatformThread(result) { try manager.getOrCreateKey() }

      case "sign":
        guard
          let arguments = call.arguments as? [String: Any],
          let payload = arguments["payload"] as? String
        else {
          result(FlutterError(
            code: "INVALID_ARGUMENT",
            message: "payload must be a base64url string.",
            details: nil
          ))
          return
        }
        self.runOffPlatformThread(result) { try manager.signPayload(payload) }

      case "deleteKey":
        self.runOffPlatformThread(result) { try manager.deleteKey() }

      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private func runOffPlatformThread(
    _ result: @escaping FlutterResult,
    _ operation: @escaping () throws -> Any
  ) {
    worker.async {
      do {
        let value = try operation()
        DispatchQueue.main.async { result(value) }
      } catch let failure as InstallationKeyFailure {
        DispatchQueue.main.async {
          result(FlutterError(
            code: failure.code,
            message: failure.message,
            details: nil
          ))
        }
      } catch {
        DispatchQueue.main.async {
          result(FlutterError(
            code: "NATIVE_KEY_ERROR",
            message: error.localizedDescription,
            details: nil
          ))
        }
      }
    }
  }
}
