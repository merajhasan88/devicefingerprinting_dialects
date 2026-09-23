# Next battery item (2026-09-19)

Companion to `DESIGN.md`. The canonical handset battery is the 16 items in DESIGN.md §25.11; the two
iOS-only additions proposed in §40.3 are items 17 and 18. On the iPhone 7, items 15 (§42) and 16 (§46)
are **PASS**. The account/token battery (items 3–8, 12, 13) is being run by the **.NET SDK session**
against the same endpoint (`https://devicefingerprinting.duckdns.org`), so it is out of scope here.

The remaining iOS-side battery work is items **17** and **18**.

---

## Item 17 — iOS clean baseline (iOS only) — already satisfied, needs formal recording

**Goal.** A legitimate, pre-signed TrollStore build reads clean — the iOS counterpart of item 1.

**Pass criterion** (§25.11 item 1 / §40.3 item 17): on a build put through
`tools/presign_trollstore_ipa.sh`, with `INTEGRITY_ALLOW_DEBUG=0` and
`INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0`: `get_task_allow: false`, `score 0`, `verdict trusted`.

**Status: MET on 2026-09-19.** When the clean `dt.ipa` (the pre-signed build) was reinstalled to
restore the phone after item 16, its scans at 16:24 UTC read `score 0, verdict trusted`, with only the
two report-only `+0` reasons (`ios_signing_identifier_bundle_mismatch`, `ios_known_fake_team_identifier`)
and **no** `ios_get_task_allow` (so get-task-allow was false). Server config at the time:
`INTEGRITY_ALLOW_DEBUG=0`, `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0`. Every clause of the criterion is met.

**Action.** Done — recorded as **PASS** in DESIGN.md §48 (2026-09-20), verified twice (2026-09-19
restore + 2026-09-20 teardown). No new build or server change was required.

---

## Item 18 — iOS fake-signature enforcement (iOS only) — the next test, but gated

**Goal.** Prove the fake-signature rule blocks a resigned / TrollStore build once it is scored (not
merely report-only).

**Procedure.**
1. On the server drop-in `/etc/systemd/system/devicetrust.service.d/test.conf`, set
   `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=1`; `daemon-reload` + restart `devicetrust`.
2. Scan the pre-signed TrollStore `dt.ipa` — it carries a donor signing identifier
   (`com.icraze.gtatracker` on this device, per §35.4/§39.1) and team id `TROLLTROLL`.
3. Expect `ios_signing_identifier_bundle_mismatch +90` → `score 100` → `verdict block`.
4. In `INTEGRITY_MODE=enforce`, attempt a login → expect `403 integrity_blocked`.
5. Restore `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0` (and `INTEGRITY_MODE=observe`) afterwards.

**Pass criterion** (§40.3 item 18): `ios_signing_identifier_bundle_mismatch +90` → `score 100`,
`block`, login `403`.

**Precondition — must be settled first (§39.5).** `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE` is `0` by
default because the rule's false-positive guard is still only a conformance fixture: **no genuinely
Apple-signed iOS build has been observed** to confirm the rule stays silent on a legitimate app.
Enabling it as policy without that observation is exactly the legitimate-user false-positive risk the
owner has said must be avoided. The rule is false-positive-safe *by construction* — a properly signed
app has signing identifier == bundle id (or the accepted `TEAMID.bundleid` .NET shape) and a real team
id, never `TROLLTROLL` (§41, §46.4) — but §39.5 wants that confirmed on a real signed build, not a
fixture. Options, owner's call:
- **(a)** Observe one real Apple-signed build (TestFlight or ad-hoc) to validate the guard, then enable
  the flag as policy.
- **(b)** Run item 18 as a **scoped, temporary demo** — flag on for the single run, off immediately
  after — explicitly recorded as a demonstration, not a production-enabled rule.
- **(c)** Defer item 18 until a real signed build exists.

Recommendation: (b) to demonstrate the enforcement now, keeping the flag off as policy until (a) is
possible — this shows the capability without shipping a rule whose false-positive guard is unproven on
a real build.

---

## Server / device state assumed by this document

- EC2 `i-0559685f02c4013b1` running, local PostgreSQL 16.15, Redis; `INTEGRITY_MODE=observe`,
  `DEVICE_POLICY_MODE=observe`, `INTEGRITY_SCORE_IOS_CODE_INTEGRITY=1`, `INTEGRITY_SCORE_IOS_FAKE_SIGNATURE=0`.
- iPhone 7 running the clean `dt.ipa` (identity intact, reads `trusted`).
- `dtadmin` DB password rotated 2026-09-19.
