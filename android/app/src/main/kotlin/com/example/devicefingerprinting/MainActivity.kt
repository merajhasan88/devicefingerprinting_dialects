// IMPORTANT: Keep this package line identical to your existing MainActivity package.
package com.example.devicefingerprinting

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
    }

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var installationKeys: InstallationKeyManager
    private lateinit var integrityProbes: IntegrityProbeManager

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        installationKeys = InstallationKeyManager(applicationContext)
        integrityProbes = IntegrityProbeManager(applicationContext)

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
                    integrityProbes.collect(required, nonce, testFixture)
                }

                else -> result.notImplemented()
            }
        }
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
                mainHandler.post {
                    result.error(
                        "NATIVE_INTEGRITY_ERROR",
                        error.message ?: "The Android native operation failed.",
                        null,
                    )
                }
            }
        }
    }
}
