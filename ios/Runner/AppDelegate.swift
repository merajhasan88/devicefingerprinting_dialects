import CoreLocation
import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate, CLLocationManagerDelegate {
  /// Matches the Android host's channel name exactly. The Dart client is
  /// platform-agnostic and talks to this same name on both platforms.
  private static let keyChannelName = "devicefingerprinting/installation_key_v2"
  private static let integrityChannelName = "devicefingerprinting/integrity_v1"
  private static let stepUpChannelName = "devicefingerprinting/stepup_key_v1"
  private static let secureScreenChannelName = "devicefingerprinting/secure_screen_v1"

  private var installationKeys: InstallationKeyManager?
  private var integrityProbes: IntegrityProbeManager?
  private var stepUpKeys: StepUpKeyManager?
  /// The app's own request for the location permission (DESIGN.md 82),
  /// answered when the person chooses; a scan never asks.
  private var locationManager: CLLocationManager?
  private var pendingLocationResult: FlutterResult?
  /// While the app PIN is typed (DESIGN.md 82): iOS lets no app block
  /// screenshots, so the window is covered whenever the screen is recorded,
  /// mirrored or sent to AirPlay.
  private var screenProtected = false
  private var captureCover: UIView?

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
    registerSecureScreenChannel(with: engineBridge.pluginRegistry)
  }

  private func registerSecureScreenChannel(with registry: FlutterPluginRegistry) {
    guard let registrar = registry.registrar(forPlugin: "DeviceTrustSecureScreen") else {
      return
    }
    let channel = FlutterMethodChannel(
      name: AppDelegate.secureScreenChannelName,
      binaryMessenger: registrar.messenger()
    )
    channel.setMethodCallHandler { [weak self] call, result in
      guard let self = self else { return }
      switch call.method {
      case "protect":
        let on = (call.arguments as? [String: Any])?["on"] as? Bool ?? false
        self.setScreenProtection(on)
        result([
          "secure": false,
          "covered_while_captured": on,
        ])
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }

  private func setScreenProtection(_ on: Bool) {
    screenProtected = on
    NotificationCenter.default.removeObserver(
      self, name: UIScreen.capturedDidChangeNotification, object: nil)
    if on {
      NotificationCenter.default.addObserver(
        self, selector: #selector(screenCaptureChanged),
        name: UIScreen.capturedDidChangeNotification, object: nil)
    }
    updateCaptureCover()
  }

  @objc private func screenCaptureChanged() {
    updateCaptureCover()
  }

  private func updateCaptureCover() {
    let cover = screenProtected && UIScreen.main.isCaptured
    if !cover {
      captureCover?.removeFromSuperview()
      captureCover = nil
      return
    }
    guard captureCover == nil, let window = activeWindow() else { return }
    let view = UIView(frame: window.bounds)
    view.backgroundColor = .black
    view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    window.addSubview(view)
    captureCover = view
  }

  private func activeWindow() -> UIWindow? {
    if let window = self.window {
      return window
    }
    return UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .flatMap { $0.windows }
      .first { $0.isKeyWindow }
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
        // Absent from an older Dart client: then nothing optional is
        // collected (DESIGN.md 80).
        let optional = arguments["optional_probes"] as? [String] ?? []
        let enabled = Set(arguments["enabled_measurements"] as? [String] ?? [])
        self.runOffPlatformThread(result) {
          collector.collect(
            requiredProbes: required,
            challengeNonce: nonce,
            testFixture: fixture,
            optionalProbes: optional,
            enabledMeasurements: enabled
          )
        }

      case "requestLocationPermission":
        self.requestLocationPermission(result)

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

  private func locationState(_ manager: CLLocationManager) -> String {
    let status: CLAuthorizationStatus
    if #available(iOS 14.0, *) {
      status = manager.authorizationStatus
    } else {
      status = CLLocationManager.authorizationStatus()
    }
    switch status {
    case .authorizedWhenInUse, .authorizedAlways:
      if #available(iOS 14.0, *), manager.accuracyAuthorization == .reducedAccuracy {
        return "approximate"
      }
      return "precise"
    case .notDetermined:
      return "undetermined"
    default:
      return "none"
    }
  }

  private func requestLocationPermission(_ result: @escaping FlutterResult) {
    let manager = locationManager ?? CLLocationManager()
    locationManager = manager
    let state = locationState(manager)
    guard state == "undetermined", pendingLocationResult == nil else {
      result(state == "undetermined" ? "none" : state)
      return
    }
    pendingLocationResult = result
    manager.delegate = self
    manager.requestWhenInUseAuthorization()
  }

  private func answerLocationRequest(_ manager: CLLocationManager) {
    let state = locationState(manager)
    guard state != "undetermined", let pending = pendingLocationResult else { return }
    pendingLocationResult = nil
    pending(state)
  }

  @available(iOS 14.0, *)
  func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
    answerLocationRequest(manager)
  }

  func locationManager(
    _ manager: CLLocationManager,
    didChangeAuthorization status: CLAuthorizationStatus
  ) {
    answerLocationRequest(manager)
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
