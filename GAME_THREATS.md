# Bots and exploits in mobile games — what this platform measures

This is for game studios that embed this platform, and for the DBAs and backend developers who set it up.
It catalogs the bot and exploit attacks that mobile games face, with multiplayer racing (a game like
Asphalt 9 Legends) as the running example. For each attack it says two things: what the platform measures
today, and what only the game's own server can decide.

**What the platform is, for a game.** It is a device-trust layer, not an anti-cheat engine and not a
game server:

- It recognises a phone across reinstalls and accounts.
- It binds every session and protected request to a key the phone cannot export.
- It scans the phone and the app for rooting, hooking, tampering and emulation.
- It scores the relationships between phones and accounts.

It never sees a race, a lap time, a score or a currency balance. The owner's principle: *"Measurements we
have to guarantee, leave business decisions for them."* Every code below is described in
[MEASUREMENTS.md](MEASUREMENTS.md). Points are the owner's defaults:

- **Integrity weights** are fixed by the product.
- **Relationship and network points** are DBA settings
  ([INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) §5).
- **Phone-setting and network signals** score 0 until the DBA gives them points.

**Three limits apply to every row.**

1. **Measurements come from the phone.** A rooted or jailbroken phone that hides itself well, or a
   modified app whose collector lies, can pass. A custom client can generate its own key and send a
   well-formed clean report, so a fully synthetic client looks like a genuine phone. There is no
   hardware attestation, by the owner's decision (DESIGN.md 66). The platform raises the cost of
   cheating; it does not make cheating impossible (guide §1).
2. **A genuine key signs whatever the app asks.** A cheat running inside the app — a hook, an edited
   value — produces correctly signed requests. Only the integrity scan and the game's own checks can
   see it.
3. **Tool names are examples of a class,** not a claim that each tool was tested. What was tested
   against real tools, and how, is in DESIGN.md.

**† Honest players show it too.** Real players use PC emulators, VPNs and ad blockers, and developer
options. Families share one tablet between accounts. Players reinstall a game to free space. A † marks
a signal of this kind: score it, ask for a step-up, or watch it. Refuse on it only knowingly. Limited
sessions and step-up (guide §7, §12) are the tools for this middle ground.

---

## 1. Bots and automation

| Attack | What the platform measures | The game's own job |
|---|---|---|
| **Headless bots**: a program that speaks the game's protocol without the app, to farm at scale. | A bot that implements the protocol with its own key and fabricates clean scans is limit 1. It cannot borrow a real player's session: a token used without its key is refused (`invalid_installation_signature`) and recorded once per token (`token_without_key`). Each fake installation arrives as a phone with no history (`new_device`, 10 points for the first `new_device_hours`). Bots usually run from data centres (`source_hosting`) †. | Make rewards depend on play the server itself verified. Count new accounts across the whole service, per network and per hour. |
| **Emulator farms**: many instances of BlueStacks, LDPlayer, MuMu, Nox or MEmu on one PC, each with an account, driven by macros or scripts. | `android_emulator` (25; on its own still the trusted band) †. Rooted emulator images also show `android_su_on_path`, `android_root_artifact`, `android_build_type_not_user`, `android_system_debuggable`, `android_ro_secure_disabled` and `android_test_keys`. Keys without secure hardware, as the phone claims: `key_software_backed`, scored only when the DBA sets `hardware_backing_policy` (owner default off). One PC's instances share an address: `source_ip`, kept where the DBA turns on `record_source_ip`. | Whether emulator players are welcome. Many games allow them and match them separately; the scan's `emulator` probe (`suspected`, via `GET /v1/business/integrity-reports`) is the measurement to place them by. |
| **Cloud phones**: hosted Android instances rented by the hour for multi-accounting and farming. | `source_hosting` (0 until the DBA sets `source_hosting_points`): the request came from a data-centre network †. Emulator and key signals as above, where the image shows them. | Whether to refuse them. The data-centre list includes cloud networks your partners use (MEASUREMENTS.md §7). |
| **Phone farms**: racks of real, unmodified phones, each with an account, often driven over USB. | A real phone's scan is clean, so the relationships carry the evidence. Accounts per phone: `device_has_multiple_accounts`, `device_has_many_accounts`, `device_account_count_block_threshold` †. Reinstall velocity: `rapid_reinstall_elevated`, `rapid_reinstall_high`, `rapid_reinstall_block_threshold` †. USB control: `android_adb_enabled` (0; eligibility rule `adb_enabled_refuses`) †. Request rate: `request_rate_anomaly`, when the DBA sets `rate_anomaly_enabled`. A shared address: `source_ip`. | Behavioural analytics: identical routines, play around the clock, synchronised sessions. |
| **On-device macros and auto-clickers**: accessibility-service bots, auto-clicker apps, Auto.js-style scripts, image-matching scripts. In a racer: one race replayed with the auto-steer assist while a macro taps through the menus, farming credits unattended. | Partly. Scripts that need root show the root signals. Control from a PC (`adb shell input`, screen mirroring) needs ADB: `android_adb_enabled` †, `android_developer_options` †. **Not measured**: which accessibility services are on, which apps are installed. | Caps on rewards per day. Detect identical races repeated and sessions nobody attends. If the game checks accessibility services itself: blind and motor-impaired players depend on them, so never refuse on them alone. |
| **PC vision bots**: a computer watches the mirrored screen and taps through USB. | `android_adb_enabled` †, `android_developer_options` †. | As above. |

## 2. Modified clients and runtime cheats

| Attack | What the platform measures | The game's own job |
|---|---|---|
| **Modded APKs and IPAs**: the game repackaged with a mod menu (free currency, all cars, more speed, no collisions), downloaded from modding sites. | **Android:** `android_signing_certificate_mismatch`, `android_package_mismatch` and, with a build baseline, `android_apk_hash_mismatch` — each 100 and hard; the install source (`installer_package`) recorded with every scan. **iOS:** `ios_team_identifier_mismatch`, `ios_bundle_id_mismatch`, `ios_signing_identifier_mismatch`, `ios_executable_hash_mismatch` — each 100 and hard; `ios_get_task_allow` (35); the fake-signature rules `ios_signing_identifier_bundle_mismatch` and `ios_known_fake_team_identifier` (report-only until enabled). | Keep every value that matters on the server: a mod that unlocks a car only on screen unlocks nothing. |
| **Memory editors**: GameGuardian-style editors on a rooted phone or in a virtual space, Cheat Engine on a PC emulator, iGameGod- or H5GG-style tools on iOS. They find and change numbers in memory: currency, nitro, top speed, timers. | **Root:** `android_root_framework_artifact`, `android_root_artifact`, `android_su_on_path`, `android_protected_mount_writable`, `android_selinux_permissive`, `android_selinux_disabled`. **Jailbreak:** `ios_jailbreak_artifact`, `ios_sandbox_escape_signal`. **An editor attached as a tracer:** `android_process_traced`, `ios_process_traced`. **Libraries injected on iOS:** `ios_hook_framework_artifact`, `ios_dyld_injection_environment`. App cloners and virtual spaces are not measured as such. | Server-authoritative state: the server holds currency, stats and inventory, and checks every change against what the game allows. |
| **Speed hacks**: the game's clock runs faster or slower because the system's time functions are hooked. In a racer: lap times nobody can drive, nitro that refills too fast. | A hook patched into a system library's code: `android_code_integrity_violation` (90). A hook in the app's own native code: `android_app_code_modified` (90). The hooking runtime itself: next row. | Plausibility checks: no time below the track's fastest possible, no speed above the car's top speed. The game knows those limits; the platform does not. |
| **Runtime hooking**: Frida; Xposed, LSPosed and Zygisk modules; Substrate or ElleKit on iOS. They replace game functions while it runs ("always first", "no collisions", "perfect nitro"), or patch the anti-cheat itself. | **Frida:** `android_frida_runtime_artifact` (90), `android_instrumentation_runtime_thread` (90), `android_glib_runtime_thread` (40), `android_frida_port_open` (75); `ios_frida_runtime_artifact` (90). **Hook frameworks:** `android_hook_framework_artifact` (80), `ios_hook_framework_artifact` (85). **Their footprint in memory:** `android_wx_memory`, `android_wx_foreign_allocator`, `android_wx_far_above_baseline`, `android_deleted_code_mapping`, `android_code_integrity_violation`, `android_app_code_modified`; `ios_app_code_modified` (report-only until enabled). | The platform covers the hook itself; the game adds the plausibility checks above. |
| **Hiding root or jailbreak**: Magisk's DenyList, Zygisk modules such as Shamiko, KernelSU, APatch, jailbreak tweak blockers on iOS. The app is shown a clean phone. | Whatever stays visible to the probes above. Hiding is an arms race, and a phone that hides everything passes (limit 1). | Server-side plausibility still catches what the hidden tool does. |
| **Debuggers**: stepping through or patching the game under a debugger. | `android_debugger_attached` (50), `android_process_traced` (55), `android_app_debuggable` (35); `ios_process_traced` (50), `ios_get_task_allow` (35). | — |
| **Save and data editing**: changing local saves, preferences, cached configuration or asset files (car physics, track data), on a rooted phone or through a backup copy. | The root signals. `android_backup_enabled` (5): the app allows OS backups, which the studio turns off in its manifest (`allowBackup`). | Keep authoritative state on the server; check downloaded assets against their hashes. |
| **Clock changes ("time travel")**: moving the phone's clock forward to finish fuel or energy refills, chest and upgrade timers, daily rewards. | A request signed with a clock more than 120 s off is refused (`access_proof_timestamp_outside_window`); so is a scan more than 90 s off (`INTEGRITY_REPORT_MAX_SKEW_SECONDS`). Protected calls fail while the clock is moved — and also for a player whose clock is simply wrong †. | Run every timer on server time. |

## 3. Network attacks

| Attack | What the platform measures | The game's own job |
|---|---|---|
| **Intercepting and editing traffic**: a proxy (Charles, mitmproxy or Burp on a PC; HttpCanary-style capture apps on the phone) used to change a race result or a reward claim in transit. | Each protected request's token, method, path, query and body are signed with the installation key. An edit in transit is refused: `access_proof_body_mismatch`, `access_proof_path_mismatch`, `access_proof_method_mismatch`, `access_proof_query_mismatch`, `access_proof_token_mismatch`. **The phone's setup:** `android_http_proxy` and `ios_http_proxy` (0; eligibility rule `http_proxy_refuses`) †. Capture apps run as a local VPN: `android_vpn_active`, `ios_vpn_active` (inferred) †. An edit made inside the app before signing is limit 2. | Validate results on the server. |
| **Replaying requests**: sending a winning result, a reward claim or a purchase confirmation again. | Each signed request carries a nonce and is accepted once: `access_proof_replay`, recorded as `request_replayed`. | Make every grant idempotent: one reward per race ID. |
| **Forged calls**: calling a reward endpoint directly, without playing. | A signed session is required (limit 1 applies). Request rate: `request_rate_anomaly`. | Grant a reward only for a race the server started and accepted. |
| **Lag switching and quitting to dodge a loss**: throttling the connection so others see a frozen car, or disconnecting just before losing. | Nothing; network timing is the game's. | Server authority over positions, penalties for disconnecting, abandoned races counted as losses. |
| **VPNs and region hopping**: for regional prices, region-locked events, matchmaking regions with weaker lobbies, or to dodge an address ban. | **On the phone:** `android_vpn_active`, `ios_vpn_active` (inferred) †; eligibility rule `vpn_active_refuses`. **By address:** `source_vpn_listed`, `source_tor_exit`, `source_hosting`, `source_vpn_observed`, `source_vpn_observed_non_hosting` — each 0 until the DBA sets points (MEASUREMENTS.md §7). Ad blockers and privacy VPNs are common among honest players. | Store prices are the store's business; match regions and event eligibility are the game's. |
| **Attacks on other players' connections**: flooding an opponent's address to knock them out of a race, where a peer-to-peer match exposes it. | The platform never shows one player another's address. | Relay match traffic through servers. |

## 4. Accounts

| Attack | What the platform measures | The game's own job |
|---|---|---|
| **Multi-accounting and smurfing**: one player with many accounts — to farm starter rewards and referrals, feed a main account, or win easily in lower leagues. | **Accounts per phone:** `device_has_multiple_accounts` (35, from 2), `device_has_many_accounts` (60, from 3), `device_account_count_block_threshold` (blocks from 4) †. The owner calibrated these defaults for financial apps; a game's DBA sets its own counts. **A reinstall onto a known phone:** `known_device_new_installation`. **Reinstall velocity:** as above. **The graph:** phones and accounts around any account (`GET /v1/business/graph`). The counts key on installation keys and reinstall hints, which a synthetic client regenerates for every account (limit 1). | The policy for second accounts. |
| **Ban evasion**: a banned player reinstalls, makes a new account, or spoofs the phone's identity. | **Ban the phone, not only the account.** A recognised device whose `recognized_devices.status` is anything but active is refused on every account and every reinstall, in any mode (`device_inactive`; `device_not_active` in its decisions). **Android:** recognition holds while ANDROID_ID does. A factory reset, another user profile (a work profile; some phone makers' "dual apps" spaces are one) or another signing key changes it. **iOS:** the installation key normally survives an uninstall (DESIGN.md 32.3). The reinstall hint (IDFV) changes once every app from the vendor is removed (guide §3). **Spoofing the identifiers** needs root or hooks, which the scan measures. A phone blocked by integrity is remembered: `device_integrity_history_block`. | Which offences ban a phone. |
| **Account takeover**: stolen passwords, phishing, SIM swaps; rare cars and currency resold. | **Tokens bound to the phone's key:** a stolen token is refused (`invalid_installation_signature`, `token_without_key`). **A new phone on the account:** `account_has_multiple_devices` †, `new_device`. **Cross-checks** (when the DBA turns them on): credential stuffing from one phone (`device_sign_in_failures_many_accounts`, `device_sign_in_unknown_accounts`); wrong passwords from other phones first (`account_sign_in_failures_elsewhere`). **Step-up:** the screen lock or an app PIN (guide §12). | Sign-in provider security, recovery flows. |
| **Account sharing and boosting**: a paid booster plays the customer's account on the booster's own phone to climb the leagues. | The account gains a phone (`account_has_multiple_devices`) †. The booster's phone collects accounts (`device_has_many_accounts`); in the graph, one phone links unrelated accounts. | Whether boosting is banned. |
| **Account selling and rerolling**: farming fresh accounts until one gets a lucky card pack, then selling it. | Reinstall velocity, accounts per phone, the account moving to a new phone. | Trade restrictions, terms of service. |
| **Recovery through support**: talking support into resetting an account's app PIN. | Support's PIN unlocks and resets are recorded (`app_pin_support_unlocked`, `app_pin_support_reset`). So is the PIN set afterwards, with the phone it was set from (`app_pin_set_after_support_reset`). | Support's own process. |
| **Referral abuse**: inviting one's own fake accounts. | Invitees on the inviter's phones: the graph, accounts per phone. Referral events that name the inviter as `subject_ref` link the accounts by a keyed hash (section 9). | Release a referral reward only after the invitee really plays. |

## 5. Economy and payments

| Attack | What the platform measures | The game's own job |
|---|---|---|
| **Fake purchases**: patched billing libraries and purchase-faking tools (Lucky Patcher-style on Android, purchase crackers on jailbroken iOS) make the game believe it was paid. | Root, jailbreak and hook signals; a repackaged build's signature mismatch. | Verify every receipt on the server with Google Play's and the App Store's server APIs before granting anything. The platform never sees a purchase. |
| **Refunds and chargebacks**: buy, spend, then refund. | Refunds posted as business events, with amount and currency (section 9). Their counts per account, and across the accounts on the same phones, reach every decision and the graph. | Revoke items on the stores' refund notices: Google Play's voided purchases, App Store server notifications. |
| **Rewarded-ad fraud**: bots or emulators watching rewarded ads for currency. | The bot and emulator signals of section 1; request rate. | Daily caps, and the ad network's own fraud checks. |
| **Gold farming and real-money trading**: bots grind currency, which is sold and handed over through gifts, trades or club donations. | The bot signals. Gift and trade events that name the recipient as `subject_ref` link every account feeding one recipient, without storing who it is. | Transfer limits and fees. |
| **Promo and gift-code abuse**: one player redeeming a code on many accounts. | Accounts per phone; redemption events that name the code as `subject_ref`. | One redemption per phone or per account. |
| **Duplication glitches**: a reconnect or a double tap that grants twice. | A signed request sent again is refused (`access_proof_replay`). A logic bug is not the platform's to see. | Idempotent grants and reconciliation. |
| **Predicting or resetting loot boxes**: client-side randomness predicted, or a pack opened again after a reinstall. | Reinstall velocity. | Draw every random outcome on the server. |

## 6. Competitive play: collusion and leagues

| Attack | What the platform measures | The game's own job |
|---|---|---|
| **Teaming and win-trading**: friends blocking or crashing others in a free-for-all race, or taking turns to win; queueing together to land in one lobby. | Accounts that share phones are linked in the graph. Whether two of them are in one race is a question the game can ask it. | Matchmaking that keeps linked accounts apart; player reports. |
| **Sandbagging**: losing on purpose to drop a league, then winning easy races. | The multi-account signals of section 4, where a second account is involved. | A skill rating that notices it. |
| **Leaderboard and event manipulation**: impossible times, or one player's accounts filling an event's top places. | Result submissions that are signed and cannot be replayed; the integrity of the phone that sent them; the multi-account signals. | Plausibility checks; review of the top entries before rewards are paid. |
| **Club and team abuse**: second accounts feeding a club's standing; joining clubs only for their rewards. | Contribution events that name the club as `subject_ref`; accounts per phone. | Cool-downs on joining and leaving. |
| **Spam bots in chat**: gold sellers and phishing links. | The bot signals of the sending accounts. | Chat moderation. |

## 7. Location-based games

| Attack | What the platform measures | The game's own job |
|---|---|---|
| **GPS spoofing**: mock-location apps (on Android they need developer options), modified clients, location spoofers on iOS. | `android_developer_options` (0; eligibility rule `developer_options_refuses`) †. Root, jailbreak and hook signals. VPN and address signals, for an address far from the claimed place. **Not measured:** the location itself, or which app supplies it. The platform collects no location. | Plausibility of speed and distance between location reports. |

## 8. A multiplayer racer, attack by attack

Online races of up to eight players, leagues, clubs, timed events, card packs and cars that refuel over
time — the features of a racer like Asphalt 9 Legends. Each cheat on them is covered above:

| Cheat | Covered in |
|---|---|
| Farming credits unattended with the auto-steer assist and a macro | §1, macros |
| More nitro, top speed or grip; cars unlocked | §2, memory editors and modded clients |
| Lap times nobody can drive | §2, speed hacks |
| Driving through other cars and walls | §2, runtime hooking |
| Editing a race result in transit; sending a win twice | §3 |
| Quitting just before a loss | §3, lag switching |
| Refuelling or finishing timers by moving the clock | §2, clock changes |
| Paid boosting through the leagues | §4, account sharing |
| Smurfs in the lower leagues | §4, multi-accounting |
| Teaming up in eight-player races | §6 |
| Second accounts feeding a club | §6 |
| Farming card packs with fresh accounts | §4, rerolling |
| Region hopping for weaker lobbies or cheaper offers | §3, VPNs |

## 9. Feeding the game's own evidence in

The game's server knows what the platform cannot: a result that failed a plausibility check, a refund, a
gift, a player report. The business API accepts these as events (guide §10). Every decision and the
graph then count them per account, and across the accounts on the same phones. The event types are the
game's own short codes, for example:

```json
{"events": [
  {"event_id": "race-88213-result", "account_id": "<account>", "type": "result_rejected",
   "occurred_at": "2026-10-15T10:21:07+00:00", "outcome": "time_below_track_minimum"},
  {"event_id": "gp-refund-5521", "account_id": "<account>", "type": "iap_refunded",
   "occurred_at": "2026-10-15T10:22:41+00:00", "amount_minor": 499, "currency": "USD"},
  {"event_id": "gift-77310", "account_id": "<account>", "type": "gift_sent",
   "occurred_at": "2026-10-15T10:23:02+00:00", "subject_ref": "<recipient>"}
]}
```

`subject_ref` is stored only as a keyed hash. Accounts that sent to the same recipient, redeemed the same
code or fed the same club are linked without the server keeping who or what it was.

**Settings a game's DBA looks at first** — each one a trade-off, set by the business:

| Setting | Trade-off |
|---|---|
| `device_accounts_elevated_count`, `device_accounts_review_count`, `device_accounts_block_count` | multi-accounting against families sharing a tablet |
| `adb_enabled_refuses`, `developer_options_refuses` | USB-driven farms and mock locations against developers and enthusiasts |
| `vpn_active_refuses`, `source_vpn_listed_points`, `source_hosting_points` and the other `source_*_points` | region hopping, cloud phones and farms against privacy VPNs and ad blockers |
| `hardware_backing_policy` | emulators and cloud phones (a claim of the phone) against old phones |
| `rate_anomaly_enabled` | scripted request rates |
| `business_event_types` | which event types the game's server may post |

## 10. What the platform does not do

- **Game state.** Positions, physics, results, currencies, timers and random draws belong to the game's
  server. A cheat the scan misses is caught only there.
- **Behaviour.** Input patterns, play schedules and win rates are the game's analytics.
- **Purchases.** Receipts are verified with the stores' server APIs.
- **Not measured on the phone:**
  - installed apps (Google Play restricts listing them);
  - accessibility services that are on;
  - mock-location settings;
  - app cloners and virtual spaces;
  - screen mirroring or recording;
  - the location.

  Each of these would identify the player more than what the platform measures today.
- **A phone that hides its compromise completely,** a collector that lies, or a fully synthetic client
  (limit 1).
