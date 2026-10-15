// IMPORTANT: Keep this package line identical to your existing MainActivity package.
package com.example.devicefingerprinting

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : FlutterActivity() {
    companion object {
        private const val KEY_CHANNEL = "devicefingerprinting/installation_key_v2"
        private const val INTEGRITY_CHANNEL = "devicefingerprinting/integrity_v1"
        private const val STEPUP_CHANNEL = "devicefingerprinting/stepup_key_v1"
        private const val LOCATION_REQUEST = 4721
    }

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var installationKeys: InstallationKeyManager
    private lateinit var integrityProbes: IntegrityProbeManager
    private lateinit var stepUpKeys: StepUpKeyManager
    // The app's own request for the location permission, answered when the
    // person chooses (DESIGN.md 82); the collector itself never asks.
    private var pendingLocationResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        installationKeys = InstallationKeyManager(applicationContext)
        integrityProbes = IntegrityProbeManager(applicationContext) { this }
        stepUpKeys = StepUpKeyManager(applicationContext)

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            KEY_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getOrCreateKey" -> runOffMainThread(result) {
                    installationKeys.getOrCreateKey()
                }

                "sign" -> runOffMainThread(result) {
                    val payload = requiredString(call, "payload")
                    installationKeys.signPayload(payload)
                }

                "deleteKey" -> runOffMainThread(result) {
                    installationKeys.deleteKey()
                }

                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            INTEGRITY_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "collect" -> runOffMainThread(result) {
                    val nonce = requiredString(call, "challenge_nonce")
                    val required = call.argument<List<String>>("required_probes")
                        ?: throw InstallationKeyFailure(
                            "INVALID_ARGUMENT",
                            "required_probes must be a list of strings.",
                        )
                    val testFixture = call.argument<String>("integrity_test_fixture")
                    // Absent from an older Dart client: then nothing optional
                    // is collected (DESIGN.md 80).
                    val optional = call.argument<List<String>>("optional_probes") ?: emptyList()
                    val enabled =
                        call.argument<List<String>>("enabled_measurements")?.toSet() ?: emptySet()
                    integrityProbes.collect(required, nonce, testFixture, optional, enabled)
                }

                // For the location and mock_location measurements: asks the
                // person once, from a button on the app's own screen.
                "requestLocationPermission" -> requestLocationPermission(result)

                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            STEPUP_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getOrCreateKey" -> runOffMainThread(result) {
                    stepUpKeys.getOrCreateKey(
                        requiredString(call, "factor"),
                        requiredString(call, "mode"),
                        call.argument<Int>("window_seconds") ?: 0,
                    )
                }

                // Stays on the main thread: it shows the system prompt, and
                // the keystore signs inside the prompt's callback.
                "sign" -> try {
                    stepUpKeys.sign(
                        this,
                        requiredString(call, "payload"),
                        call.argument<String>("reason") ?: "Approve this operation",
                        call.argument<String>("mode") ?: StepUpKeyManager.MODE_PER_USE,
                    ) { outcome ->
                        outcome.fold(
                            { signature -> result.success(signature) },
                            { error ->
                                val failure = error as? InstallationKeyFailure
                                result.error(
                                    failure?.errorCode ?: "NATIVE_STEPUP_ERROR",
                                    error.message ?: "The step-up signature failed.",
                                    null,
                                )
                            },
                        )
                    }
                } catch (error: InstallationKeyFailure) {
                    result.error(error.errorCode, error.message, null)
                }

                "deleteKey" -> runOffMainThread(result) {
                    stepUpKeys.deleteKey()
                }

                else -> result.notImplemented()
            }
        }
    }

    private fun locationState(): String = when {
        checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED -> "precise"
        checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED -> "approximate"
        else -> "none"
    }

    private fun requestLocationPermission(result: MethodChannel.Result) {
        if (locationState() == "precise" || pendingLocationResult != null) {
            result.success(locationState())
            return
        }
        pendingLocationResult = result
        requestPermissions(
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,
            ),
            LOCATION_REQUEST,
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == LOCATION_REQUEST) {
            pendingLocationResult?.success(locationState())
            pendingLocationResult = null
        }
    }

    // Delivers the confirm-credential result the step-up key uses on API < 30.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (::stepUpKeys.isInitialized && stepUpKeys.onActivityResult(requestCode, resultCode)) {
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun requiredString(call: MethodCall, field: String): String {
        return call.argument<String>(field)
            ?: throw InstallationKeyFailure(
                "INVALID_ARGUMENT",
                "$field must be a string.",
            )
    }

    private fun runOffMainThread(
        result: MethodChannel.Result,
        operation: () -> Any,
    ) {
        worker.execute {
            try {
                val value = operation()
                mainHandler.post { result.success(value) }
            } catch (error: InstallationKeyFailure) {
                mainHandler.post {
                    result.error(error.errorCode, error.message, null)
                }
            } catch (error: Throwable) {
                // Name the exception and its cause: a release build's log output
                // is suppressed on the test OPPO, so the message shown in the app
                // is the only diagnostic there is.
                val detail = buildString {
                    append("The Android native operation failed: ")
                    append(error.javaClass.name)
                    error.message?.let { append(": ").append(it) }
                    error.cause?.let { cause ->
                        append(" (cause ").append(cause.javaClass.name)
                        cause.message?.let { append(": ").append(it) }
                        append(")")
                    }
                    append(" at ")
                    append(error.stackTrace.take(6).joinToString(" < ") {
                        "${it.className.substringAfterLast('.')}.${it.methodName}:${it.lineNumber}"
                    })
                }
                mainHandler.post {
                    result.error("NATIVE_INTEGRITY_ERROR", detail, null)
                }
            }
        }
    }
}
