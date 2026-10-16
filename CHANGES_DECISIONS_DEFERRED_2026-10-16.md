# Changes, decisions and deferred work — 2026-10-16

For the owner and for reviewers. It lists five things, in this order:

1. what changed since the last review archive (`devicetrust-review-2026-10-13.tar.gz`, HEAD `89928ae`);
2. the owner's decisions since then, in the owner's words;
3. the work the owner deferred and said will be done;
4. the questions still waiting on the owner;
5. what is not yet verified.

`DESIGN.md` is the full record, with the reasoning, commits and test results; the section numbers below
point into it. The archive's `GIT_HEAD.txt` names the exact commit, and `GIT_LOG.txt` lists every
commit.

---

## 1. What changed since 2026-10-13

There are 124 commits since `89928ae`. The schema went from 14 to **24**, with every migration written
for both PostgreSQL and SQL Server.

### §76 — the critical review of 2026-10-13: R1–R6, and the business API (migrations 015–018)

**Approvals (R1)**
- An approval now accepts exactly the reasons and points the approver saw.
- Counted reasons are covered only up to the count the approver saw.
- Collection problems are never covered.
- There is no automatic cover by default; the DBA can turn it on.

**Relationship limits (R2)**
- Linking a phone to an account now re-checks the limits under a lock in the same transaction.
- A change in between answers 409 `relationship_changed`.

**Evidence quality (R3, R4)**
- Collection problems now count once (+30) and stay out of the device's integrity memory.
- Evidence is labelled `complete`, `incomplete`, `invalid` or `legacy`.
- Two counters were added:
  - `complete_evidence_paths` requires a complete scan on the paths the DBA lists;
  - `incomplete_evidence_review_after` escalates evidence that stays incomplete.

**Sign-out (R6)**
- `POST /v1/auth/logout` revokes the session family.
- Account requests answer 401 `session_revoked` once the family is revoked.

**The business API** (server to server)
- Events in.
- Out: the phone–account graph, the feed of approvals that stopped covering, and event counts in every
  decision.
- Nothing from it is scored.

**Legacy approvals:** approvals granted before migration 016 are carried over (`legacy_acceptances` `carry`).

### §77 — the server's own observations (migration 019)

- The server now records wrong passwords, sign-ins to unknown accounts, failed step-ups, exhausted
  approval budgets, step-up key re-enrolments, denials, stolen tokens used without their key, and
  replayed requests.
- Every decision carries the counts.
- Eight cross-check rules score only where the DBA sets `cross_checks_enabled`.
- A counter outage is recorded as degraded evidence, never as a rate of zero.

### §78 — step-up by screen lock, by an app PIN the server checks, or both (migration 020)

- `stepup_method` is a DBA setting; the owner's default is `app_pin`.
- The DBA can also list `app_pin_required_paths`.
- There is one PIN per account. It is stored as bcrypt over a keyed HMAC, and locks after
  `app_pin_max_failures` (5) wrong tries.

### §79 — who configures what (migration 021): the owner's answers to gaps G1–G10

- **G1:** the relationship rules are now DBA settings.
- **G8:** session lifetimes: `refresh_idle_days` (30) and `session_max_days` (0, off).
- **Support:** support staff can unlock or reset an app PIN (`app_pin_support`, off by default).
- **G4:** the app reads the DBA's step-up policy at runtime.
- **G5:** a feed of every integrity report (`GET /v1/business/integrity-reports`), plus
  `MEASUREMENTS.md`.
- **G7:** a settings reference generated from the migrations.
- **Map:** `WHO_CONFIGURES_WHAT.md` maps every setting and duty to the party that owns it.

### §80 — the phone's OS and network; measurements switched on by two keys (migration 022)

- Every scan volunteers:
  - a `device` probe: the OS version, and on Android the **security patch level**;
  - a `network` probe: whether a VPN or an HTTP proxy is in use.
- A VPN or proxy costs 0 points, with DBA eligibility rules to refuse them.
- **Optional measurements need two keys:** the DBA's `optional_measurements`, and the app's build
  setting.
- The DBA may record each request's source address and User-Agent.
- MAC address and IMEI were dropped.

### §81 — VPN exits by address, the SDK set, the platform scope (migration 023)

- Public VPN, data-centre and Tor lists ship with the server; DevOps refreshes them daily with
  `tools/fetch_network_lists.py`.
- Each server can learn VPN exits from its own Android phones (`vpn_exit_learning`, off).
  - An address counts only with at least 3 phones and a 90% share within 30 days.
  - All three numbers are DBA settings.
- Every decision carries `source_network`, with 0-point reasons the DBA can weight.
- The scope is now:
  - five client SDKs;
  - financial apps, games and government **mobile** apps;
  - never one named customer.
- **`GAME_THREATS.md`:** 40 bot and exploit attacks on mobile games, each mapped to what is measured
  and what stays with the game's server.

### §82 — what can read or drive the phone, screen capture, location, the patch age, the PIN entry (migration 024)

**Six optional measurements, behind the two keys**
- `accessibility`: Accessibility services, and the keyboard in use;
- `notification_access`;
- `other_access`: device administrators, and AnyDesk, TeamViewer QuickSupport, RustDesk and AirDroid;
- `screen_capture`;
- `location`;
- `mock_location`.

The two location measurements also need the person's own OS permission, which only the app asks for.

**Where each app came from.** The server judges each app holding one of these capabilities as:
- the system's;
- from an app store (the DBA's `app_store_installers`);
- sideloaded;
- or unknown, which is never evidence.

**Rules:** 14 eligibility rules, all off by default. A security patch older than
`security_patch_max_age_days` is a finding.

**PIN entry:** while the app PIN is typed, Android blocks screenshots and recording of the window,
hides other apps' windows drawn over it, and drops touches that pass through them. iOS covers the
window while the screen is captured.

**Collectors:** Android 5, iOS 4.

**Deleting VPN sightings** is the DBA's job; the guide's §15 gives the statements.

### §82.1 — default points

| Finding | Points |
|---|---|
| Accessibility on in a sideloaded app | 45 |
| Sideloaded keyboard, notification reader or device administrator | 30 each |
| Remote-control app installed | 20 |
| Screen capture | 30 |
| Mock location | 40 |
| Security patch over 365 days old | 10 |
| The four broad "not part of the system" findings | 0 |

All of these are DBA settings.

### Documents and tests

- New: `MEASUREMENTS.md`, `WHO_CONFIGURES_WHAT.md`, `GAME_THREATS.md`, `data/network_lists/`.
- The integration guide grew from §7 to §15.
- `HANDOFF_TO_DOTNET_2026-09-30.md` grew from §17 to §25.
- 129 DBA settings.
- Offline gate **110/110**.
- Conformance suite: from 73 to **91** checks. Live in normal mode on 2026-10-15: **68 passed, 0 failed, 23 skipped**.

---

## 2. The owner's decisions since 2026-10-13

**2026-10-13 (§76)**
- **R3:** collection problems count once and stay out of the device memory, with a DBA switch back.
- **The two counters:** apply them.
- **R1:** approvals accept the exact reasons and points seen. There is no automatic cover by default;
  it is the business's decision.
- **R4:** contradictory evidence scores +30 as `invalid`.
- **First-party fraud:** everything DBA-configurable; the graph combined with business events —
  *"Measurements we have to guarantee, leave business decisions for them."*
- **Approvals granted before the upgrade:** carry them over; the business's users must not have to
  re-confirm.

**2026-10-14**
- The long-term list: *"You can get started on these long-term items. I want to fix any hole and
  breach in our defenses."* Section 3 has the list and the state of each item.
- **Step-up method:** *"build every option but make the screenlock and app PIN checked by server as DBA
  configurable"*. The default was then set to the app PIN.
- **Denied approvals:** *"Lower the denial points and keep it at limited but make the setting DBA
  configurable."*
- **Approval budget:** *"go with your recommendation but as ever keep it DBA configurable"*. It counts
  hours in which the budget ran out, not refusals.
- **The cross-check window:** a DBA setting.
- **The role split:** *"Leave it to them to figure out business logic but our job is 1) give them
  defaults, 2) give them every possible measurement from app, 3) a means to apply logic on servers and
  the app that may differ from defaults"*.
- **Who switches settings on:** *"configurable from the app **and** turned ON from server side by
  DBA"*.
- **The gaps:**
  - Support unlock: *"build the mechanism"*.
  - G1: *"put them under DBA"*.
  - G4: *"modify it so it can follow DBA choice"*.
  - G5: *"build it"*.
  - G7: *"update it now"*.
  - G8: *"make it DBA configurable. 30-day is default"*.
  - G2, G3, G6 and G10 were deferred; see section 3.

**2026-10-15**
- **OS version and optional measurements:** *"yes send the OS version. Other measurements such as MAC
  address, IMEI, IP address, user agent: keep them optional but provide a means for app team to enable
  them."*
- **MAC address and IMEI:** *"MAC and IMEI: drop them"*.
- **VPN exits:**
  - *"The VPN-address project: we need it if iphone is blind to VPNs."*
  - Collection: *"go with 1 and 2"* — the public lists and the deployment's own Android phones.
  - A separate bit for VPNs outside hosting companies.
  - *"only my customers… Nothing paid… I dont want to put my poor cloudfront out for abuse"*: no
    central list, no CloudFront.
  - The owner confirmed that the project stores nothing; each customer's server holds its own lists
    and sightings.
- **SDKs:** *"yes lets have react native too (we already have .NET)… I will note this down and have
  separate claude's build each."*
- **Scope:**
  - *"Leave payactiv out of it as this is a broad platform now and I want to include games and govt
    site protection alongside financial apps."*
  - Then: *"I didnt mean government websites but government mobile apps."*
- **Games:** *"a comprehensive list of bot and other exploitative attacks that may be specific for
  games especially multiplayer like Asphalt 9 Legends"*, delivered as `GAME_THREATS.md`.
- **Deleting VPN sightings:** *"Deletion should be DBA job. Just mention it in integration document
  very clearly."*
- **New measurements:** *"Build mechanism to store these and make it configurable by relevant teams:
  accessibility services, fake gps, screen recording or mirroring, location, access to notifications,
  other access. Also start sending phone's security update level. Build App pin screen proposal too."*
- **Scores:** *"Why 0 score? Put reasonable default scores."*

---

## 3. Deferred — the owner said these will be done

| Item | The owner's words | What it is |
|---|---|---|
| **G2 — a Flutter package** | *"defer it to later after we have finished testing. It will be done. Note it down. Just not now."* (2026-10-14) | A Flutter plugin with the Dart API, the models and the Android and iOS native code; the harness then depends on it. The package's name, versioning and where it is published are the owner's call. |
| **G3 — a guide for app developers** | *"do after G2"* | Today an app developer reads the guide and copies code out of the harness. |
| **G6 — the front page** | *"after G3"*; and the open-source project *"which I will eventually host on a website called necessary.com or necessary.io"* (2026-10-15) | `README.md` is still Flutter's template. |
| **G10 — SQL Server** | *"fill the gaps, we will do that afterwards"* (2026-10-14) | One RDS round. It covers the suite for migrations 015–024, the guide's T-SQL deletion of VPN sightings, and binding ID parameters as `varchar(36)` in the SQL Server dialect (§74). Nothing ships without the suite on both engines. |
| **The other client SDKs (G9)** | *"I will note this down and have separate claude's build each."* | Native Android (Kotlin), native iOS (Swift) and React Native, each built in a Claude session of its own. .NET exists; Flutter is this repository. |
| **The iPhone round** | *"Run iphone after the review work. Would need another codemagic build or we could go with gitlab actions."* (2026-10-13) | It needs a new iOS build: iOS collectors 3 and 4, the location request and the PIN protection have never been compiled. |

**The long-term defence list** (2026-10-14, *"I want to fix any hole and breach in our defenses"*), in
the owner's order:

| # | Item | State |
|---|---|---|
| 1 | Cross-checks from what the server already sees | **Done** (§77) |
| 2 | Per-operation "fresh and complete scan required" | **Partly.** The per-path requirement exists (`complete_evidence_paths`). Binding a scan to the exact operation it approves is not built. |
| 3 | Recovery for single-phone users (route 3) before any customer turns enforcement on | **Server side built** (identity-system assertions, guide §7). It needs each customer's identity backend; the harness has none. |
| 4 | Events from other services: credential changes, recovery, networks, payees | **Largely covered.** The business events API takes them, with payees stored only as keyed hashes (§76), and §80–§81 record source networks. Anything that carries personal data is the owner's call. |
| 5 | Per-installation history: coverage disappearing, flips between suspicious and clean, build changes | **Not built.** Observe-only at first, because OS updates will trigger it. |
| 6 | Runtime baselines per build, OS and CPU type, from the release pipeline | **Not built.** This is also the open part of review finding R5: the runtime allowances rest on name and shape heuristics. |
| 7 | Observation-mode metrics: false restrictions, recoveries, detector coverage | **Not built.** |
| 8 | The review's four-question verdict (protocol, evidence, findings, decision) | **Labels exist** (evidence quality). The structured response belongs in the next API version. |

---

## 4. Waiting on the owner

**Defaults for the older 0-point signals.** These were left at 0 by earlier decisions and asked
about on 2026-10-15:
- VPN, HTTP proxy, developer options and ADB;
- the five address-based `source_*_points`.

**Defaults chosen on the owner's instruction** (§82.1), to confirm or retune:
- the points;
- the 365-day patch age;
- the store list, which leaves out vivo's and Honor's stores because their package names could not be
  verified.

**A shared VPN-exit list across deployments.** It was costed (S3 plus CloudFront's free plan) and not
built. It is needed only if customers are to share what they learn.

**Two leftovers from the SQL Server round of 2026-10-12** (§74):
- `~/.mssql_pw` on the EC2 server;
- the `devicetrust-db` security group's port-1433 rule. It still exists, checked on 2026-10-16; there is
  no RDS instance.

---

## 5. Not yet verified

- **iOS:** the Swift is uncompiled: iOS collector 4, the location request and the secure screen.
- **Real phones for §80–§82.** Only the emulator was used for:
  - whether OEM phones let the app see other apps' installers;
  - how phone makers' preinstalled apps are classified;
  - fake GPS on a real phone.

  G4 (the app following the DBA's step-up policy) has not run on a phone either.
- **An app from Google Play counted as a store app.** The emulator has no Play Store.
- **A screen recording made by a recorder app.** A command-line recording was tried and was not
  detected.
- **SQL Server:** migrations 015–024, and the guide's T-SQL deletion.

---

## 6. State on 2026-10-16

- **Test server:** the EC2 server is stopped. PostgreSQL 16.15 is at schema 24, in observe mode for
  both integrity and policy, with every setting at the owner's default, including §82.1.
- **Test data in the database:**
  - the emulator's reports, including a mock Paris location;
  - the test accounts;
  - four VPN sightings of the test machine's address.
- **Billing:** nothing but the stopped instance's disk. No RDS, no snapshots, no Elastic IPs, no NAT.
- **Emulator:** `integrity_root_lab` (API 36) keeps the harness. The test-only apps were removed.
