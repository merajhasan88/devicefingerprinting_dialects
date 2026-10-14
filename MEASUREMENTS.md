# Measurements — everything the server measures, and where to read it

The owner's principle: *"Measurements we have to guarantee, leave business decisions for them."* This
catalog lists every measurement this project produces — what the phone reports, what the server derives
from it, what the server itself observes — so that a business can build its own rules on them. The
default points are the owner's defaults; a DBA changes them in `risk_policy_settings`
([INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) §5).

`tools/check_security_regressions.py` checks that every reason code, observation kind and probe field the
server source uses appears in this file, so the catalog cannot fall behind the code.

| Measurement | Stored in | A business reads it through |
|---|---|---|
| What the phone measured in a scan (`probe_results`), with the reasons and score derived from it | `integrity_reports` | `GET /v1/business/integrity-reports` (every report, paged); the latest per phone in `GET /v1/business/graph` |
| The relationship reasons and the context of each decision | `risk_policy_decisions` | SQL; the app receives its own as `trust_policy` |
| What the server itself observed (wrong passwords, failed step-ups, stolen tokens, support actions) | `server_observations` | counts in every decision's `context.server_observations`; per account and phone in `GET /v1/business/graph` |

**`probe_results` identify a phone** — its model, OS build, installed tools, the app's install source. A
business that reads them holds device-identifying data and treats it as such. The server stores no name,
e-mail, telephone number or network address with them.

---

## 1. What the phone measures (`probe_results`)

A scan answers a challenge the server issued; the server chooses the probes (mandatory ones on every
scan, plus a random draw of the optional ones) and the installation key signs the complete report. The
phone never sends a score. The signed report:

| Field | Meaning | Stored |
|---|---|---|
| `challenge_id`, `challenge_nonce` | the challenge it answers; each answers once | `integrity_reports.challenge_id` |
| `installation_id` | the installation whose key signed it | yes |
| `platform` | `android` or `ios` | yes |
| `collector_version` | the native collector's version (Android 3, iOS 2 today) | yes |
| `collected_at` | the phone's clock, which must be within the allowed skew | checked, not stored |
| `probe_results` | one object per requested probe, below | yes, as sent |
| `version` | the report format, 1 | checked |

The server adds `report_id`, `device_id`, the SHA-256 of the signed bytes (`report_sha256`), its
reasons, score, verdict, evidence quality and `created_at`. The native collector also tells the app
the OS version (`sdk_int` on Android, `os_version` on iOS) and the name of any debug fixture; the app
checks the nonce echo and does not send these, so they are not stored.

Every probe answers `status`: `ok`, `error` (with `error`, and on Android `error_type`) or
`unsupported` (with `reason`). An `error` is a collection problem, never a clean result (§2,
`integrity_probe_failed:<probe>`). **Bold** fields are the server's evidence contract
(`_PROBE_REQUIRED_FIELDS`): an `ok` probe without them is `integrity_probe_incomplete:<probe>`.
*Italic* fields are read when present (`_PROBE_OPTIONAL_FIELDS`). The rest are recorded as sent.

### Android

Mandatory: `app_identity`, `debug_state`, `root_files`, `system_properties`, `runtime_maps`,
`tracer`, `root_shell`, `selinux`, `mounts`, `frida_ports`, `instrumentation_threads`,
`exec_mappings`, `code_integrity`, `developer_settings`. Optional: `emulator`.

| Probe | Fields | What it measures |
|---|---|---|
| `app_identity` | **`package_name`**, **`apk_sha256`**, **`cert_sha256`** (list), **`debuggable`**, **`allow_backup`**, `version_name`, `version_code`, `installer_package`, `source_dir` | the installed app: package, the base APK's SHA-256, the signing certificates' SHA-256, its flags, its install source |
| `debug_state` | **`debugger_connected`**, **`waiting_for_debugger`** | a Java debugger |
| `tracer` | **`tracer_pid`**, `seccomp`, `no_new_privs` | `/proc/self/status`: another process tracing the app |
| `root_files` | **`found_paths`**, **`test_keys`**, `build_tags` | known root, su and framework paths that exist; test-keys in the build tags |
| `root_shell` | **`su_found`**, `su_path` | whether `su` resolves from the app's shell |
| `system_properties` | **`properties`**: `ro.secure`, `ro.debuggable`, `ro.build.type`, `ro.build.tags`, `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.boot.vbmeta.device_state`, `ro.boot.veritymode` | build and boot-security properties |
| `selinux` | **`mode`** (`enforcing`/`permissive`/`disabled`/`unknown`), **`getenforce`**, **`enforce_value`** | SELinux, from two views; `unknown` is never evidence |
| `mounts` | **`protected_rw_mounts`** | `/system`, `/vendor`, `/product`, `/odm`, `/system_ext` mounted read-write |
| `runtime_maps` | **`suspicious_tokens`**, *`suspicious_line_count`*, *`maps_lines`* | Frida, Gadget, Objection, hook and root framework names in `/proc/self/maps` |
| `frida_ports` | **`open_ports`** | local ports 27042 and 27043 accepting connections |
| `instrumentation_threads` | **`frida_threads`**, **`glib_threads`**, **`token_threads`**, *`thread_count`* | thread names Frida's runtime compiles in (`gum-js-loop`, `pool-frida`, GLib's) — survives a renamed library |
| `exec_mappings` | **`wx_mappings`**, **`deleted_exec_mappings`**, *`wx_bytes`*, *`wx_size_classes`*, *`wx_smallest_bytes`*, *`wx_largest_bytes`*, *`deleted_exec_own_code`*, *`deleted_exec_jit`*, *`anon_exec_labeled`*, *`anon_exec_unlabeled`*, *`maps_lines`*, *`samples`* | writable-and-executable memory and its shape; executable memory backed by deleted files |
| `code_integrity` | **`checked`**, **`diff_bytes`**, **`core_compared_bytes`**, **`ext_compared_bytes`**, **`ext_diff_bytes`**, **`app_compared_bytes`**, **`app_diff_bytes`**, `core_diff_bytes`, `ext_libs_diff`, `app_libs_diff`, `diffed_libs`, `reason`, *`core_expected_bytes`*, *`core_skipped_bytes`*, *`core_unreadable_bytes`*, *`core_complete`*, *`ext_expected_bytes`*, *`ext_skipped_bytes`*, *`ext_unreadable_bytes`*, *`ext_complete`*, *`app_expected_bytes`*, *`app_skipped_bytes`*, *`app_unreadable_bytes`*, *`app_complete`*, *`protect_restore_failures`*, *`xom_regions_unlocked`*, *`xom_regions_unreadable`*, *`elapsed_ms`* | system libraries (`core`, `ext`) and the app's own native code (`app`) compared in memory against their files on disk — an inline hook changes the bytes |
| `developer_settings` | **`developer_options_enabled`**, **`adb_enabled`** | the phone's settings |
| `emulator` | **`suspected`**, `reasons`, `model`, `manufacturer`, `product`, `hardware` | build values typical of an emulator |

### iOS

Mandatory: `app_identity`, `code_signing`, `debugger`, `jailbreak_files`, `sandbox`, `dyld_images`
(and `code_integrity` once `INTEGRITY_SCORE_IOS_CODE_INTEGRITY` is on; until then the collector sends
it unasked). Optional: `environment`, `simulator`.

| Probe | Fields | What it measures |
|---|---|---|
| `app_identity` | **`bundle_id`**, **`executable_sha256`**, `version_name`, `version_code`, `executable_bytes` | the installed app and its main executable's SHA-256 |
| `code_signing` | **`signing_identifier`**, **`team_identifier`**, **`get_task_allow`**, `signed`, `signature_absent` | the executable's own code signature, parsed from the Mach-O |
| `debugger` | **`traced`** | `P_TRACED` on the process |
| `jailbreak_files` | **`found_paths`**, `checked_count` | known jailbreak paths that exist |
| `sandbox` | **`write_outside_sandbox_succeeded`**, `probe_path` | whether the app can write outside its sandbox |
| `dyld_images` | **`suspicious_tokens`**, `suspicious_image_count`, `image_count` | Frida, Substrate and jailbreak names among the loaded images |
| `environment` | **`dyld_insert_libraries`** | the `DYLD_INSERT_LIBRARIES` variable |
| `simulator` | **`is_simulator`**, `model` | the simulator, and the hardware model identifier |
| `code_integrity` | **`checked`**, **`app_diff_bytes`**, **`app_compared_bytes`**, `diff_bytes`, `core_compared_bytes`, `core_diff_bytes`, `ext_compared_bytes`, `ext_diff_bytes`, `ext_libs_diff`, `app_libs_diff`, `diffed_libs`, `system_images_unreadable`, `system_bucket_reason` | the app's own code in memory against its file |

---

## 2. Integrity reasons (derived by the server from a scan)

Each reason carries `code`, `points`, `message` and `hard`. The integrity score is the sum of the points,
capped at 100; a hard reason blocks. Bands: 0–29 trusted, 30–59 elevated, 60–89 review, 90+ block. A
*report-only* reason scores 0 and carries `report_only: true` and `proposed_points` — what it would cost
if enabled.

Collection problems (DESIGN.md 66): `integrity_probe_failed:<probe>` (a requested probe answered
`error`), `integrity_probe_incomplete:<probe>` (an `ok` probe without its contract fields) and
`integrity_evidence_invalid:<probe>` (measurements that contradict each other). Under the owner's
default (`collection_problems_block` 0) each scores 0 and one `integrity_evidence_incomplete` row adds
30 for all of them; where the DBA sets it to 1, each scores 30 and that summary row does not appear.
`integrity_evidence_persistently_incomplete` adds 30 more after `incomplete_evidence_review_after` (3)
incomplete scans in a row, under either setting.

| Code | Points | Hard | Report-only | Platform | Meaning |
|---|---|---|---|---|---|
| `integrity_evidence_incomplete` | 30 |  |  | both | N requested probe(s) measured nothing usable; a complete scan clears this. Only under `collection_problems_block` 0. |
| `integrity_evidence_persistently_incomplete` | 30 |  |  | both | N integrity scans in a row could not be completed; send a complete scan. |
| `key_hardware_backing_unreported` | 100 | yes |  | both | `hardware_backing_policy` = required, and this installation never reported how its key is stored. |
| `key_software_backed` | 100 or 30 | when required |  | both | The installation key is software-backed (a claim of the phone): 100 and hard under `required`, 30 under `advisory`. |
| `android_wx_memory` | 60 |  |  | Android | Writable-and-executable memory is mapped into the process. |
| `android_wx_foreign_allocator` | 45 |  |  | Android | Writable-executable memory of a size this build's runtime never allocates is mapped into the process. |
| `android_wx_far_above_baseline` | 40 |  |  | Android | Writable-executable memory is more than `wx_far_above_baseline_percent` of this build's baseline. |
| `android_wx_above_baseline` | 0 |  |  | Android | Writable-executable memory exceeds this build's baseline within the expected growth; advisory. |
| `android_package_mismatch` | 100 | yes |  | Android | Installed package name does not match the server baseline. |
| `android_signing_certificate_mismatch` | 100 | yes |  | Android | APK signing certificate is not in the server allow-list. |
| `android_apk_hash_mismatch` | 100 | yes |  | Android | Installed base APK hash does not match the configured build baseline. |
| `android_app_debuggable` | 35 |  |  | Android | The installed application is debuggable. |
| `android_backup_enabled` | 5 |  |  | Android | The application permits OS backup/transfer. |
| `android_debugger_attached` | 50 |  |  | Android | A debugger is attached to the application process. |
| `android_process_traced` | 55 |  |  | Android | TracerPid indicates that another process is tracing the app. |
| `android_root_framework_artifact` | 75 |  |  | Android | Root-management framework artifacts were visible. |
| `android_root_artifact` | 50 |  |  | Android | Root/su artifacts were visible. |
| `android_test_keys` | 25 |  |  | Android | Build tags contain test-keys. |
| `android_su_on_path` | 50 |  |  | Android | The su command is discoverable from the application process. |
| `android_build_type_not_user` | 45 |  |  | Android | The OS build type is not a production user build. |
| `android_verified_boot_not_green` | 60 |  |  | Android | Verified Boot state is not green. |
| `android_bootloader_not_locked` | 60 |  |  | Android | Bootloader/flash lock property is not locked. |
| `android_vbmeta_not_locked` | 60 |  |  | Android | VBMeta device state is not locked. |
| `android_boot_state_unavailable` | 15 |  |  | Android | The device reported no Verified Boot / AVB state. |
| `android_ro_secure_disabled` | 50 |  |  | Android | ro.secure is disabled. |
| `android_system_debuggable` | 35 |  |  | Android | ro.debuggable is enabled. |
| `android_selinux_disabled` | 70 |  |  | Android | SELinux reports disabled. |
| `android_selinux_permissive` | 45 |  |  | Android | SELinux reports permissive mode. (An unknown mode scores 0.) |
| `android_protected_mount_writable` | 55 |  |  | Android | A protected system mount appears writable. |
| `android_frida_runtime_artifact` | 90 |  |  | Android | Frida/Gadget/Objection artifacts were mapped into the process. |
| `android_hook_framework_artifact` | 80 |  |  | Android | Hook/root framework artifacts were mapped into the process. |
| `android_frida_port_open` | 75 |  |  | Android | A common local Frida server port is accepting connections. |
| `android_instrumentation_runtime_thread` | 90 |  |  | Android | A Frida/Gum instrumentation runtime thread is present in the process. |
| `android_glib_runtime_thread` | 40 |  |  | Android | GLib runtime threads, a common Frida dependency, are present in the process. |
| `android_code_integrity_violation` | 90 |  |  | Android | A system library's executable code differs from its on-disk image (inline hook). |
| `android_app_code_modified` | 90 |  |  | Android | The application's own native code differs from its packaged image. |
| `android_code_integrity_partial` | 30 |  | yes | Android | Code integrity compared only part of its targets. |
| `android_code_integrity_restore_failed` | 30 |  | yes | Android | The scanner could not restore a mapping's original protection after reading it. |
| `android_deleted_code_mapping` | 55 |  |  | Android | Executable memory backed by a deleted file is mapped into the process. |
| `android_app_code_recompiled` | 0 |  |  | Android | The app's own compiled code was replaced on disk while it ran (a system recompilation after an install or update; advisory). |
| `android_emulator` | 25 |  |  | Android | The runtime resembles an Android emulator. |
| `android_developer_options` | 0 |  |  | Android | Developer options are enabled (advisory). The DBA may make it an eligibility rule: `developer_options_refuses`. |
| `android_adb_enabled` | 0 |  |  | Android | ADB is enabled (advisory). The DBA may make it an eligibility rule: `adb_enabled_refuses`. |
| `ios_bundle_id_mismatch` | 100 | yes |  | iOS | Bundle identifier does not match the server baseline. |
| `ios_executable_hash_mismatch` | 100 | yes |  | iOS | Executable hash does not match the configured build baseline. |
| `ios_signing_identifier_mismatch` | 100 | yes |  | iOS | Code-signing identifier does not match the server baseline. |
| `ios_team_identifier_mismatch` | 100 | yes |  | iOS | Team identifier does not match the server baseline. |
| `ios_get_task_allow` | 35 |  |  | iOS | get-task-allow is enabled for this application. |
| `ios_signing_identifier_bundle_mismatch` | 90 |  | until enabled | iOS | The code-signing identifier does not match the bundle identifier, which a legitimately signed application never does. |
| `ios_known_fake_team_identifier` | 25 |  | until enabled | iOS | The team identifier matches a known fake-signing marker. |
| `ios_process_traced` | 50 |  |  | iOS | The process is being traced/debugged. |
| `ios_jailbreak_artifact` | 75 |  |  | iOS | Jailbreak filesystem artifacts were visible. |
| `ios_sandbox_escape_signal` | 100 | yes |  | iOS | The app successfully wrote outside its sandbox. |
| `ios_frida_runtime_artifact` | 90 |  |  | iOS | Frida/Gadget/Objection images were loaded into the process. |
| `ios_hook_framework_artifact` | 85 |  |  | iOS | Jailbreak/hooking framework images were loaded into the process. |
| `ios_dyld_injection_environment` | 90 |  |  | iOS | DYLD_INSERT_LIBRARIES is set. |
| `ios_simulator` | 25 |  |  | iOS | The app is running in the iOS simulator. |
| `ios_app_code_modified` | 90 |  | until enabled | iOS | The application's own code differs in memory from its packaged image. |

*Until enabled*: report-only until the environment switch `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE`
(the two signing rules) or `INTEGRITY_SCORE_IOS_CODE_INTEGRITY` turns it on.

---

## 3. Relationship reasons (the server's risk decision)

Each decision combines the latest scan with the relationships between phones, installations and
accounts — opaque identifiers only. The score is the sum of the points; the DBA's bands (owner defaults
30 / 60 / 90) make it allow, step-up, review or block. Each points value names its setting; 0 switches
a rule off.

| Code | Points (setting, owner default) | Meaning |
|---|---|---|
| `installation_not_active` | 100, blocks | The cryptographic installation is not active. |
| `device_not_active` | 100, blocks | The recognized device has been administratively blocked. |
| `new_device` | `new_device_points` 10 | The phone was first seen less than `new_device_hours` (24) ago. |
| `known_device_new_installation` | `known_device_new_installation_points` 15 | A new installation was correlated to a phone already recognized (a reinstall). |
| `device_has_multiple_accounts` | `device_accounts_elevated_points` 35 | The phone is linked to `device_accounts_elevated_count` (2) or more accounts. |
| `device_has_many_accounts` | `device_accounts_review_points` 60 | … to `device_accounts_review_count` (3) or more. |
| `device_account_count_block_threshold` | 100, blocks | … to `device_accounts_block_count` (4) or more. |
| `account_has_multiple_devices` | `account_devices_elevated_points` 35 | The account is linked to `account_devices_elevated_count` (2) or more phones. |
| `account_has_many_devices` | `account_devices_review_points` 60 | … to `account_devices_review_count` (3) or more. |
| `account_device_count_block_threshold` | 100, blocks | … to `account_devices_block_count` (5) or more. |
| `rapid_reinstall_elevated` | `reinstall_elevated_points` 35 | `reinstall_elevated_count` (3) reinstalls in `reinstall_window_hours` (24). |
| `rapid_reinstall_high` | `reinstall_high_points` 60 | `reinstall_high_count` (4) or more. |
| `rapid_reinstall_block_threshold` | 100, blocks | `reinstall_block_count` (5) or more. |
| `integrity_report_missing` | `integrity_report_missing_points` 40 | No signed scan exists for this installation. |
| `integrity_report_stale` | `integrity_report_stale_points` 35 | The latest scan is older than `integrity_freshness_seconds` (600). |
| `native_integrity_risk` | the latest scan's integrity score | The latest scan's own score, carried into the decision. |
| `device_integrity_history_block` | `device_integrity_history_block_points` 50 | Another installation on this phone was blocked by integrity within `integrity_device_memory_hours`. |
| `request_rate_unavailable` | 0 | The request-rate counter could not be read; the decision was made without it. |
| `request_rate_anomaly` | `rate_anomaly_points` 30 | More than `rate_anomaly_max_requests` in `rate_anomaly_window_seconds` (only with `rate_anomaly_enabled`). |
| `population_outlier` | `population_points` 30 | `population_baseline_metric` above `population_baseline_threshold` (only with `population_baseline_enabled`). |

The server's cross-checks (DESIGN.md 77) score only where the DBA sets `cross_checks_enabled`; their
counts are in every decision's context either way. Each rule has `<code>_count` and `<code>_points`,
counted over `cross_check_window_hours` (24):

| Code | Count, points | What is counted |
|---|---|---|
| `account_sign_in_failures_elsewhere` | 5, 30 | wrong-password sign-ins to the account from other phones before this phone joined it |
| `device_sign_in_failures_many_accounts` | 3, 60 | different accounts with a wrong-password sign-in from this phone |
| `device_sign_in_unknown_accounts` | 5, 30 | sign-ins from this phone to accounts that do not exist |
| `device_stepup_failures` | 3, 30 | step-up proofs from this phone that did not verify |
| `device_approvals_denied` | 1, 30 | this phone's approval requests for the account that were denied; `device_approvals_denied_effect` limit (default: held at review) or points |
| `device_approval_budget_exhausted` | 2, 30 | budget periods in which this phone found the account's hourly approval budget spent |
| `device_stepup_reenrolments` | 2, 30 | step-up keys the account re-enrolled on this phone |
| `device_app_pin_failures` | 3, 30 | wrong app PINs for the account from this phone |

---

## 4. What the server observes itself (`server_observations`)

Recorded with the account (when there is one), the phone and the installation — the server's own opaque
IDs. Never updated or deleted.

| Kind | `code` | When |
|---|---|---|
| `sign_in_failed` | `invalid_credentials`, `app_pin_set_invalid_credentials`, `stepup_reenrol_invalid_credentials` | a wrong password: at sign-in, when setting an app PIN, when re-enrolling a step-up key |
| `sign_in_unknown_account` | `invalid_credentials` | a sign-in to an account that does not exist |
| `stepup_failed` | the refusal's code, e.g. `stepup_signature_invalid`, `stepup_factor_mismatch` | a step-up proof that did not verify (a missing one is not an attempt) |
| `approval_budget_exhausted` | `upgrade_budget_exhausted` | an approval request refused because the account's hourly budget was spent; once per budget period |
| `stepup_reenrolled` | `stepup_reenrolled` | a step-up key re-enrolled |
| `token_without_key` | `invalid_installation_signature` | a valid token used without its installation key — a stolen token; once per token |
| `request_replayed` | `access_proof_replay` | a signed request sent again; once per request |
| `app_pin_failed` | `app_pin_invalid`, `app_pin_locked` | a wrong app PIN, and the one that locked it |
| `app_pin_set` | `app_pin_set`, `app_pin_set_after_support_reset` | an app PIN set or replaced, and from which phone |
| `app_pin_support_unlocked` | the support ticket's reference | support unlocked the account's app PIN |
| `app_pin_support_reset` | the support ticket's reference | support opened a reset of the account's app PIN |

---

## 5. A decision's context

Every risk decision carries the measurements it was made on, stored in `risk_policy_decisions` with it:

`platform`, `registration_method`, `registration_confidence`, `installation_established`,
`installation_device_confirmed_at`, `installation_created_at`, `installation_status`, `device_status`,
`device_created_at`, `device_age_hours`, `device_installation_count`, `device_account_count`,
`projected_device_account_count`, `account_device_count`, `projected_account_device_count`,
`account_already_linked_to_device`, `recent_reinstall_count`, `reinstall_window_hours`, `integrity`
(the latest scan's state), `integrity_mode`, `integrity_freshness_seconds`, `device_integrity_memory`,
`device_integrity_memory_hours`, `server_observations` (the counts per phone, per account and per
account on the phone, with `window_hours` and whether they were `scored`), `request_rate`,
`held_by_denial`, `rate_limiter` when the counter was unavailable, and `business_events_30d` — counts by
type of the business events of the account, and of every account linked to the phone, over 30 days
(DESIGN.md 76), where the business API is configured.
