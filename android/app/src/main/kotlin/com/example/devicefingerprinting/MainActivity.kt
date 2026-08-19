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
        private const val CHANNEL =
            "devicefingerprinting/installation_key_v2"
    }

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var installationKeys: InstallationKeyManager

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        installationKeys = InstallationKeyManager(applicationContext)

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            CHANNEL,
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
                        "NATIVE_KEY_ERROR",
                        error.message ?: "The Android installation-key operation failed.",
                        null,
                    )
                }
            }
        }
    }
}
