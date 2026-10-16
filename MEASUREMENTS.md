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
e-mail or telephone number with them, and no network address or location unless the DBA and the app both
turn it on (§6).

---

## 1. What the phone measures (`probe_results`)

A scan answers a challenge the server issued; the server chooses the probes (mandatory ones on every
scan, plus a random draw of the optional ones) and the installation key signs the complete report. A
current collector also **volunteers** `device` and `network` on every scan — never part of the plan, so
an older app that does not send them loses nothing — and answers the **optional measurements** the
challenge lists in `optional_probes` (§6). The phone never sends a score. The signed report:

| Field | Meaning | Stored |
|---|---|---|
| `challenge_id`, `challenge_nonce` | the challenge it answers; each answers once | `integrity_reports.challenge_id` |
| `installation_id` | the installation whose key signed it | yes |
| `platform` | `android` or `ios` | yes |
| `collector_version` | the native collector's version (Android 5, iOS 4 today) | yes |
| `collected_at` | the phone's clock, which must be within the allowed skew | checked, not stored |
| `probe_results` | one object per probe, below | yes, as sent — except an optional measurement the DBA does not request, which is dropped |
| `enabled_measurements` | the optional measurements this app's developers enabled, whether or not the server asked; an older app leaves it out | yes, as `enabled_by_app` in the measurements' statuses, below |
| `version` | the report format, 1 | checked |

The server adds `report_id`, `device_id`, the SHA-256 of the signed bytes (`report_sha256`), its
reasons, score, verdict, evidence quality and `created_at`. The native collector hands the app its
`probes` with `collector_version`, `platform`, `challenge_nonce_echo`, `sdk_int` (Android) or
`os_version` (iOS) and `test_fixture_applied`; the app checks the nonce echo and the platform and sends
the probes as `probe_results`. The OS version reaches the server inside the `device` probe (collectors
from Android 4 and iOS 3); a report from an older app has none.

Checked against the test database on 2026-10-15: the latest report from a real Android phone (15
probes, 87 fields) and from the real iPhone (9 probes, 47 fields) use only the fields named below.

Every probe answers `status`: `ok`, `error` (with `error`, and on Android `error_type`),
`unsupported` (with `reason`) or, for an optional measurement this app's developers did not enable,
`not_enabled`. An `error` in a probe of the plan is a collection problem, never a clean result (§2,
`integrity_probe_failed:<probe>`); a volunteered or optional probe is never one. **Bold** fields are the server's evidence contract
(`_PROBE_REQUIRED_FIELDS`): an `ok` probe without them is `integrity_probe_incomplete:<probe>`.
*Italic* fields are read when present (`_PROBE_OPTIONAL_FIELDS`). The rest are recorded as sent.

### Android

Mandatory: `app_identity`, `debug_state`, `root_files`, `system_properties`, `runtime_maps`,
`tracer`, `root_shell`, `selinux`, `mounts`, `frida_ports`, `instrumentation_threads`,
`exec_mappings`, `code_integrity`, `developer_settings`. Optional: `emulator`. Optional measurements
(§6), from collector 5: `local_addresses`, `accessibility`, `notification_access`, `other_access`,
`screen_capture`, `location`, `mock_location`.

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
| `device` (volunteered, collector 4) | *`release`*, *`sdk_int`*, *`security_patch`*, *`manufacturer`*, *`brand`*, *`model`*, *`device`*, *`build_id`*, *`fingerprint`* | the OS version and API level, **the security patch level** (how current the phone's patches are), the hardware model, the build |
| `network` (volunteered, collector 4) | *`vpn_active`*, *`http_proxy_configured`*, *`transports`* (`wifi`, `cellular`, `ethernet`, `vpn`), *`interfaces`* (names only) | whether a VPN is up — the system's connectivity service is asked about every network, not only the default — and whether an HTTP proxy is set; needs `ACCESS_NETWORK_STATE`, a normal permission granted at install |
| `local_addresses` (optional, §6) | *`addresses`*: a list of `interface`, `address` | the phone's own IP addresses per interface, link-local ones left out |
| `accessibility` (optional, §6; collector 5) | *`services`*: a list of apps; *`keyboard`*: one app; *`settings_only`*: component names; *`truncated`* | every Accessibility service that is on, and the keyboard in use (the default input method). Each app is `package`, `service` (its component class), `system` (part of the phone's system) and `installer` (the package that installed it, empty for none); `system` and `installer` are left out where Android hides the app from this one. `settings_only` lists services the system settings name but the Accessibility manager does not report — an Android bug let a service hide that way until the December 2022 patch |
| `notification_access` (optional, §6; collector 5) | *`listeners`*: a list of apps; *`truncated`* | every app allowed to read the phone's notifications (one-time codes among them) |
| `other_access` (optional, §6; collector 5) | *`device_admins`*, *`remote_access_apps`*: lists of apps; *`truncated`* | the active device-administrator apps, and which known remote-control apps are installed: AnyDesk, TeamViewer QuickSupport, RustDesk, AirDroid — a list compiled into the app, which Android lets it check without seeing other apps |
| `screen_capture` (optional, §6; collector 5) | *`recording`*, *`external_displays`* | whether the app's window was being recorded at the scan (Android 15 and later; left out before), and how many displays besides the phone's own show content (casting, mirroring, an external screen) |
| `location` (optional, §6; collector 5) | *`permission`* (`precise`, `approximate`, `none`), *`latitude`*, *`longitude`*, *`accuracy_m`*, *`age_seconds`*, *`provider`* | the last location the phone already knows — never a fresh fix, never a prompt; coordinates only where the app holds the location permission and the phone has a fix |
| `mock_location` (optional, §6; collector 5) | *`permission`*, *`mock`*, *`age_seconds`* | whether that last location came from a mock-location app; no coordinates |

A collector sends at most 32 apps per list and sets `truncated` when the phone had more. Every entry is
checked: a malformed one (an app without a valid package name, an unknown field, a list longer than 64)
refuses the report with 400 `invalid_integrity_probe`, never silently dropped (review F1, DESIGN.md 83).

**Each measurement's status** (review F1, DESIGN.md 83). With every report the server stores the status
of every measurement a current collector of the platform answers — planned, volunteered or optional,
scored or not — so it always knows what a scan did and did not measure. They are stored in
`measurement_status` and returned as `measurements` in the scan's answer, in `/v1/integrity/me`, in each
decision's `integrity` and in the business report feed: `{"status": {measurement: status},
"enabled_by_app": [...]}`.

| Status | Meaning |
|---|---|
| `ok` | measured |
| `failed` | it answered `error`, or nothing usable |
| `unsupported` | this phone cannot measure it (iOS cannot see other apps) |
| `not_enabled` | the server asked; this app's developers did not enable it |
| `not_requested` | the server did not ask: an optional measurement the DBA does not list, or an optional probe not drawn this time |
| `absent` | asked for or expected, and not answered: an older or a modified app |
| `no_permission` | `location`, `mock_location`: the person has not given the app the location permission |
| `no_fix` | `location`, `mock_location`: the phone knows no location |
| `stale` | `location`, `mock_location`: the location is older than `location_max_age_seconds` (600) |

`enabled_by_app` is the report's `enabled_measurements`, or `null` from an app that does not send it. A
report stored before migration 025 has no statuses.

### iOS

Mandatory: `app_identity`, `code_signing`, `debugger`, `jailbreak_files`, `sandbox`, `dyld_images`
(and `code_integrity` once `INTEGRITY_SCORE_IOS_CODE_INTEGRITY` is on; until then the collector sends
it unasked). Optional: `environment`, `simulator`. Optional measurements (§6), from collector 4:
`local_addresses`, `screen_capture`, `location`, `mock_location`; iOS shows an app no other app, so
`accessibility`, `notification_access` and `other_access` answer `unsupported`.

| Probe | Fields | What it measures |
|---|---|---|
| `app_identity` | **`bundle_id`**, **`executable_sha256`**, `version_name`, `version_code`, `executable_bytes` | the installed app and its main executable's SHA-256 |
| `code_signing` | **`signing_identifier`**, **`team_identifier`**, **`get_task_allow`**, `signed`, `signature_absent`, `signature_parse_error`, `code_directory_flags`, `entitlement_count` | the executable's own code signature, parsed from the Mach-O |
| `debugger` | **`traced`** | `P_TRACED` on the process |
| `jailbreak_files` | **`found_paths`**, `checked_count` | known jailbreak paths that exist |
| `sandbox` | **`write_outside_sandbox_succeeded`**, `probe_path` | whether the app can write outside its sandbox |
| `dyld_images` | **`suspicious_tokens`**, `suspicious_image_count`, `image_count` | Frida, Substrate and jailbreak names among the loaded images |
| `environment` | **`dyld_insert_libraries`** | the `DYLD_INSERT_LIBRARIES` variable |
| `simulator` | **`is_simulator`**, `model` | the simulator, and the hardware model identifier |
| `code_integrity` | **`checked`**, **`app_diff_bytes`**, **`app_compared_bytes`**, `diff_bytes`, `core_compared_bytes`, `core_diff_bytes`, `ext_compared_bytes`, `ext_diff_bytes`, `ext_libs_diff`, `app_libs_diff`, `app_images_compared`, `diffed_libs`, `system_images_unreadable`, `system_bucket_reason`, `app_segment_compared_bytes`, `app_segment_diff_bytes` (the last two telemetry, never scored) | the app's own code in memory against its file |
| `device` (volunteered, collector 3) | *`os_version`*, *`os_build`* (collector 4), *`model_identifier`* (for example `iPhone9,3`) | the OS version and build — iOS has no separate security patch level: its security fixes ship as OS versions, and the build tells a Rapid Security Response apart — and the hardware model |
| `network` (volunteered, collector 3) | *`vpn_active`*, *`http_proxy_configured`*, *`scoped_interfaces`* | iOS gives other apps no VPN API: a VPN is **inferred** from the interfaces the system proxy settings are scoped to (`utun`, `ipsec`, `ppp`, `tun`, `tap`) — a heuristic, so the names are sent with it; the proxy from the system proxy settings |
| `local_addresses` (optional, §6) | *`addresses`*: a list of `interface`, `address` | as on Android |
| `screen_capture` (optional, §6; collector 4) | *`recording`*, *`external_displays`* | whether the screen is being recorded, mirrored or sent to AirPlay (`UIScreen.isCaptured`), and how many other screens are attached |
| `location` (optional, §6; collector 4) | *`permission`*, *`latitude`*, *`longitude`*, *`accuracy_m`*, *`age_seconds`* | as on Android |
| `mock_location` (optional, §6; collector 4) | *`permission`*, *`mock`*, *`accessory`*, *`age_seconds`* | iOS 15 and later: whether that location was simulated by software, or produced by an accessory |

---

## 2. Integrity reasons (derived by the server from a scan)

Each reason carries `code`, `points`, `message`, `hard` and `category`. The integrity score is the sum of
the points, capped at 100; a hard reason blocks. Bands: 0–29 trusted, 30–59 elevated, 60–89 review, 90+
block. A *report-only* reason scores 0 and carries `report_only: true` and `proposed_points` — what it
would cost if enabled.

The `category` says what kind of evidence a reason is (review F2, DESIGN.md 83):

- **`integrity`** — the phone or the app is compromised or not genuine: root, hooks, a debugger,
  modified code, a wrong signature.
- **`condition`** — what the phone allows or is doing, which its owner can change: developer options,
  ADB, a VPN, an HTTP proxy, an old security patch, and the findings of the optional measurements
  (Accessibility, the keyboard, notification access, device administrators, remote-control apps,
  screen recording, another display, a simulated location).
- **`collection`** — a check that measured nothing usable (below).

Conditions add at most `conditions_points_cap` (owner default 60) together, so on their own they reach
review, never a block. A reason the cap reduced keeps what it would have scored in `points_before_cap`.
The device memory (`device_integrity_history_block`, §3) remembers only the integrity findings
(`finding_score`), so a clean scan clears a condition.

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
| `android_vpn_active` | `vpn_active_points` 10 |  |  | Android | A VPN is active on this phone. Eligibility rule: `vpn_active_refuses`. |
| `android_http_proxy` | `http_proxy_points` 15 |  |  | Android | An HTTP proxy is configured on this phone. Eligibility rule: `http_proxy_refuses`. |
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
| `ios_vpn_active` | `vpn_active_points` 10 |  |  | iOS | A VPN appears to be active on this phone (inferred). Eligibility rule: `vpn_active_refuses`. |
| `ios_http_proxy` | `http_proxy_points` 15 |  |  | iOS | An HTTP proxy is configured on this phone. Eligibility rule: `http_proxy_refuses`. |
| `android_accessibility_sideloaded` | `accessibility_sideloaded_points` 45 |  |  | Android | An Accessibility service is on in an app no app store installed: the banking-trojan signature, though a phone maker's preloaded app with no installer looks the same. Eligibility rule: `accessibility_sideloaded_refuses`. |
| `android_accessibility_non_system` | `accessibility_non_system_points` 0 |  |  | Android | An Accessibility service is on in an app that is not part of the system, store apps included: screen readers and password managers too. Eligibility rule: `accessibility_non_system_refuses`. |
| `android_accessibility_hidden` | `accessibility_hidden_points` 30 |  |  | Android | An Accessibility service the system setting names is missing from the Accessibility list (`settings_only`): an Android bug let malware hide that way until the December 2022 patch. Eligibility rule: `accessibility_hidden_refuses`. |
| `android_keyboard_sideloaded` | `keyboard_sideloaded_points` 30 |  |  | Android | The keyboard in use is an app no app store installed; a keyboard sees everything typed. Eligibility rule: `keyboard_sideloaded_refuses`. |
| `android_keyboard_non_system` | `keyboard_non_system_points` 0 |  |  | Android | The keyboard in use is not part of the system, store keyboards included. Eligibility rule: `keyboard_non_system_refuses`. |
| `android_notification_access_sideloaded` | `notification_access_sideloaded_points` 30 |  |  | Android | An app no app store installed can read notifications, one-time codes among them. Eligibility rule: `notification_access_sideloaded_refuses`. |
| `android_notification_access_non_system` | `notification_access_non_system_points` 0 |  |  | Android | An app that is not part of the system can read notifications: smartwatch apps too. Eligibility rule: `notification_access_non_system_refuses`. |
| `android_device_admin_sideloaded` | `device_admin_sideloaded_points` 30 |  |  | Android | A device-administrator app no app store installed is active; malware uses it to resist removal. Eligibility rule: `device_admin_sideloaded_refuses`. |
| `android_device_admin_non_system` | `device_admin_non_system_points` 0 |  |  | Android | A device-administrator app that is not part of the system is active: company phone management too. Eligibility rule: `device_admin_non_system_refuses`. |
| `android_remote_access_app` | `remote_access_app_points` 20 |  |  | Android | A remote-control app is installed (not necessarily running). Eligibility rule: `remote_access_app_refuses`. |
| `android_screen_captured` | `screen_capture_points` 30 |  |  | Android | The app's screen was being recorded during the scan (Android 15 and later). Another display alone is `android_external_display`. Eligibility rule: `screen_capture_refuses`. |
| `ios_screen_captured` | `screen_capture_points` 30 |  |  | iOS | The screen was recorded, mirrored or on AirPlay during the scan (`UIScreen.isCaptured`). Eligibility rule: `screen_capture_refuses`. |
| `android_external_display` | `external_display_points` 10 |  |  | Android | A display besides the phone's own was on during the scan: a cast, a mirror or a monitor — not proof that the app's screen is captured. Eligibility rule: `external_display_refuses`. |
| `ios_external_display` | `external_display_points` 10 |  |  | iOS | Another screen was attached during the scan. Eligibility rule: `external_display_refuses`. |
| `android_mock_location` | `mock_location_points` 40 |  |  | Android | The phone's last location came from a mock-location app, and is younger than `location_max_age_seconds` (600; an older fix is kept, not scored). Eligibility rule: `mock_location_refuses`. |
| `ios_mock_location` | `mock_location_points` 40 |  |  | iOS | The phone's last location was simulated by software. Eligibility rule: `mock_location_refuses`. |
| `android_security_patch_outdated` | `security_patch_outdated_points` 10 |  |  | Android | The security patch level is older than `security_patch_max_age_days` (owner default 365; 0 = never). Eligibility rule: `security_patch_outdated_refuses`. |

These score the DBA's `*_points` (owner defaults shown; DESIGN.md 82, 83): the sideloaded holders and
the deliberate manipulations score, while what screen readers, password managers, store keyboards,
smartwatch apps and company phone management also hold stays at 0. A sideloaded app is also not part of
the system, so its two findings add up. Developer options and ADB stay at 0, as decided after review R1
(DESIGN.md 69): with them on, a clean phone scored 33, a step-up. A deployment that refuses them turns on
their eligibility rules.

An app's source, for the `_sideloaded` findings (DESIGN.md 82): **system** where the phone marks it part of
the system; **store** where its installer is one of `app_store_installers` (owner default: Google Play,
Samsung Galaxy Store, Huawei AppGallery, the HeyTap and OPPO markets, Xiaomi GetApps, Amazon Appstore —
add your market's own); **sideloaded** where anything else or nothing installed it — a browser, a file
manager, `adb`, another app's installer, as malware droppers do; **unknown** where Android hid the app's
details, which is never evidence. A phone maker's preloaded app that is not a system app and has no
installer counts as sideloaded: look at your phones' reports before turning a `_sideloaded` rule on.

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
| `source_vpn_listed` | `source_vpn_listed_points` 10 | The request came from an address on the public VPN list (§7). |
| `source_tor_exit` | `source_tor_exit_points` 30 | The request came from a Tor exit (§7). |
| `source_hosting` | `source_hosting_points` 15 | The request came from a hosting or data-centre network not known as a VPN (§7). |
| `source_vpn_observed` | `source_vpn_observed_points` 10 | The request came from an address this server's Android phones show to be a VPN exit, in a hosting network or where that is unknown (§7). |
| `source_vpn_observed_non_hosting` | `source_vpn_observed_non_hosting_points` 10 | The same, outside hosting networks: a home or office VPN (§7). |

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
IDs — and, for a support action, the business API caller that did it (`actor`, review F3). Never updated
or deleted.

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
`held_by_denial`, `rate_limiter` when the counter was unavailable, `source_ip` and `user_agent` where the
DBA records them (§6), `source_network` (§7), and `business_events_30d` — counts by
type of the business events of the account, and of every account linked to the phone, over 30 days
(DESIGN.md 76), where the business API is configured. The stored context also keeps the decision's
`assessment`, the four answers of §8. A decision judged on a scan made for its operation (DESIGN.md
84.3) carries `operation_scan` — `report_id`, `operation_sha256`, `age_seconds` — and one where observe
mode let such a request through without that scan names the refusal enforce mode would have given
(`operation_scan.problem`).

**Which settings and which code** (review F4, DESIGN.md 83). `policy_version` is the version of the DBA's
settings the decision was made under: 16 hex characters, the same for the same settings and different
after any change to any setting. It is keyed with the server's root secret, so it cannot be used to
guess the settings, and a new root secret gives every version anew. The stored row's context also has
`server_build`: the first 12 hex characters of the SHA-256 of the server file that made the decision.
It is never returned to the phone. The same `server_build` and `policy_version` judge the same
measurements the same way; a different `server_build` means only that the server was redeployed —
`git log` says what changed. The decision's time is its `created_at`, and the scan it used is
`integrity.report_id`.

Nothing is re-scored. Each scan keeps the score and reasons it was given when it arrived, and stores
`policy_version` and `server_build` with them. In `integrity` (the latest scan) and in
`device_integrity_memory`, `policy_version` is the version the scan was scored under, and
`policy_current` says whether the settings are still that version (`true`), have changed since
(`false` — a new scan is scored under the current settings), or cannot be told because the scan was
stored before migration 025 (`null`).

---

## 6. Optional measurements, and what a phone will not give

Owner decision of 2026-10-15 (`DESIGN.md` §80): measurements that identify a person's phone or network
stay optional, and the parties who answer for them switch them on.

| Measurement | Switched on by | Where it lands |
|---|---|---|
| `local_addresses` — the phone's own IP addresses | **both**: the DBA lists it in `optional_measurements`, and the app's developers enable it in the app (the reference app: `--dart-define=MEASURE_LOCAL_ADDRESSES=true`). Asked for and not enabled, the phone answers `not_enabled` | the report's `probe_results`; dropped before storing whenever the DBA does not request it |
| `source_ip` — the address a request came from, as the server sees it (behind the configured proxies) | the DBA: `record_source_ip` | each risk decision's context |
| `user_agent` — the request's User-Agent header, cut at 256 characters | the DBA: `record_user_agent`. The Flutter client sends `Dart/<version> (dart:io)` unless the app sets its own | each risk decision's context |
| `vpn_active`, `http_proxy_configured` | always measured by current collectors (a yes/no, no address) | the `network` probe; reasons at the DBA's `vpn_active_points` (10) and `http_proxy_points` (15); eligibility rules `vpn_active_refuses`, `http_proxy_refuses` |
| `accessibility`, `notification_access`, `other_access` — which apps can read the screen, the keyboard, the notifications, or administer or remotely control the phone (Android) | **both**, as for `local_addresses`: the DBA lists it, the app enables it (the reference app: `MEASURE_ACCESSIBILITY`, `MEASURE_NOTIFICATION_ACCESS`, `MEASURE_OTHER_ACCESS`). A person's Accessibility services can reveal a disability | the report's `probe_results`; reasons at the DBA's points with eligibility rules (§2) |
| `screen_capture` — the screen recorded, cast or mirrored during the scan | **both** (`MEASURE_SCREEN_CAPTURE`); Android 15 and later also need the app to declare `DETECT_SCREEN_RECORDING`, a normal permission | as above |
| `location` — the last location the phone knows; `mock_location` — whether it was simulated | **both** (`MEASURE_LOCATION`, `MEASURE_MOCK_LOCATION`), **and** the person grants the app the OS location permission, which only the app asks for. Without it the probe answers `permission: none` and nothing else | the report's `probe_results`; `mock_location` has its reason and eligibility rule |

**Measurements a path requires** (review F1, DESIGN.md 83). An eligibility rule such as
`accessibility_sideloaded_refuses` judges only a scan that has its measurement: a phone that does not
send it is never refused by the rule. Where that matters, the DBA lists the measurements a scan must
have in `required_measurements` (empty by default) and the paths they apply to in
`required_measurements_paths` (empty: every request the integrity check guards). Only status `ok` meets
a requirement; an iPhone is never asked for what it cannot measure (`accessibility`,
`notification_access`, `other_access`). The scan's answer says `requirements_satisfied` and lists
`missing_requirements`, each measurement with its status. A scan without one, under
`missing_measurement_action`:

- **`limit`** (owner default) — treated like an elevated scan: a step-up proof satisfies a request
  that accepts one, a sign-in gives a limited session, and anything else answers 403
  `integrity_measurements_missing` until a new scan has them;
- **`refuse`** — always 403 `integrity_measurements_missing`.

An approval never covers a missing measurement. Observe mode reports and never refuses.

Kept as long as the decisions and reports are: the business's retention policy applies to them.

Location was outside the platform until the owner asked for it on 2026-10-15 (DESIGN.md 82); it is
the most identifying measurement here, so it needs the person's own permission as well as the DBA's
request and the app's setting.

**Not collected — dropped by the owner (2026-10-15).** Neither is measurable by an ordinary app on
current phones:

- **MAC address.** iOS has answered every app with the same constant (`02:00:00:00:00:00`) since iOS 7.
  Android has done the same for the Wi-Fi API since Android 6, hides the address from apps targeting
  Android 11 or later, and from Android 10 uses a random address per Wi-Fi network anyway.
- **IMEI.** iOS has no API for it. From Android 10 it needs a privilege only system apps hold; up to
  Android 9 it needs the "make and manage phone calls" permission prompt, and Google Play requires
  disclosure of persistent device identifiers. A device-owner app on a company-managed phone is the
  exception.

---

## 7. Where a request came from (`source_network`)

`DESIGN.md` §81. iOS gives apps no way to see a VPN, so the server recognises VPN exits by the address
a request comes from. Every risk decision's context carries `source_network`, five yes/no answers, each
**None** where the server cannot know; the address itself is not kept there.

| Key | Yes when | From |
|---|---|---|
| `vpn_listed` | the address is in a VPN provider's network | the X4BNet VPN list shipped with the server (IPv4) |
| `tor_exit` | the address is a Tor exit | the Tor Project's exit list (IPv4) |
| `hosting` | the address is in a hosting or data-centre network | the X4BNet data-centre list (IPv4) |
| `vpn_observed` | this server's own Android phones show the address to be a VPN exit | learning, below; None while it is off |
| `vpn_observed_non_hosting` | the same, and the address is outside hosting networks — a home or office VPN | learning and the hosting list; None where hosting is unknown |

**Learning** (`vpn_exit_learning`, off by default). Android tells the app whether its own traffic goes
through a VPN — the transports of the app's default network, in the `network` probe — and the server
sees the address that traffic arrives from. That is the phone's own report, which a modified app can
falsify: a learned exit is an inference from your phones' reports, not a verified fact (review F5).
Each Android scan adds a sighting to `vpn_exit_sightings`: the address, the phone (`device_id`), and
whether it came through a VPN (`last_via_vpn_at`, `scans_via_vpn`) or direct (`last_direct_at`,
`scans_direct`). Each phone counts by its latest sighting there: one that came through a VPN once and
direct since is a direct phone. Only phones the server has known for `vpn_exit_min_device_age_days` (7)
count at all, so freshly made-up phone identities cannot label an address. An address counts as a VPN
exit once at least `vpn_exit_min_phones` (3) different phones came through a VPN from it within
`vpn_exit_window_days` (30), and they are at least `vpn_exit_min_share_percent` (90) of the phones seen
from it then. A phone's own address — a home line, a carrier's shared pool — carries mostly direct
traffic, even where an ad blocker or firewall app uses Android's VPN interface and sends traffic out
from the phone's own address; a VPN server's address carries only VPN traffic. iOS cannot say where its
traffic goes, so an iPhone is never a witness — and is recognised by the address it shares with them.
The sightings are personal data (an address per phone), kept even when `record_source_ip` is off, never
read by the business API and never published. The server never deletes them: deleting those outside the
window is the DBA's job ([INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) §15 gives the statements).

The lists are refreshed by DevOps with `tools/fetch_network_lists.py` (daily); the server re-reads a
changed file within a minute. Their sources and licences are in `data/network_lists/SOURCES.md`. The
data-centre list includes cloud networks your own servers and partners use: an address in it is a
measurement, never by itself a reason to refuse.

---

## 8. The four answers (`assessment`)

Every scan response, every risk decision — returned, and stored in its row's context — and every refusal
that carries a scan or a decision answers four questions apart (DESIGN.md 84.2), so that a valid
signature is never read as a clean phone, nor a trusted verdict on thin evidence as a clean one. It
restates what the scan and the policy decided; it changes no outcome.

| Answer | Fields |
|---|---|
| `protocol` — was the request genuine | `result` is `valid`: a request that fails a check is refused with that check's own code and never gets this far. `token` (`device` or `account`), `proof` (`access_proof_v2`), `installation_key` (`verified`), `nonce` (`single_use`), `step_up_proof` (a step-up proof was verified for this request). A scan adds `challenge` (`single_use`) and `report_signature` (`verified`) |
| `evidence` — what was measured | `quality` — `complete`, `partial`, `incomplete`, `invalid`, `legacy`, `none` (no scan) or `unknown` (a scan from before migration 015); `report_id`, `age_seconds`, `fresh`; `requirements_satisfied` and `missing_requirements` (the DBA's required measurements the scan lacks, §6) |
| `findings` — what suggests abuse, and who supplied the facts | one per reason, with its `code` and `points`; `kind` — a scan's reasons are `integrity`, `condition` or `collection` (§2), the relationship policy's are `relationship`, `behaviour` (§4 and the request rate), `network` (§7), `administration` (a revoked phone or installation), `integrity` (the scan's score as the policy counts it, the device memory) or `collection` (no scan, an old one, a counter that could not be read); `provenance` — `phone` (the phone's own scans, which a compromised phone can forge; a learned VPN exit rests on other phones' reports), `server` (what the server saw itself) or `business` (the business's events) |
| `decision` — what the evidence calls for, and what was granted | `recommended`: `allow`, `step_up`, `scan` (a fresh or complete scan), `review` or `deny` — the stricter of `integrity` (the latest scan judged as enforce mode judges it: its verdict, the eligibility rules, required measurements, complete-evidence paths, the device memory) and `relationship` (the policy's action; absent for a scan); `enforced`, per mode. In a response also `allowed` — `full`, `limited`, `step_up`, `scan`, `review` or `deny` — and `allowed_by` when the request passed although the evidence called for more: `step_up_proof`, `approval`, `observe_mode`, or `settings` (for example an elevated relationship risk, which refuses nothing unless `elevated_risk_refuses` is 1) |

The stored row keeps the answers as evaluated, before anything was granted (no `allowed`); its
`acceptance_id` names an approval that let the request pass. The business report feed gives each stored
scan its answers as judged when it arrived (`as_scored`: its verdict, its reasons). In observe mode every
decision still says what enforce mode would have done: compare `decision.recommended` with
`decision.enforced`.

