#!/usr/bin/env python3
"""A scripted second phone for limited-session handset tests (DESIGN.md 73).

Plays "the other phone of the same account" with the conformance suite's
software keys, so one real handset can exercise both sides of route 2
(approve and be approved). Keys, tokens and request IDs persist in a state
file (default ./second_phone_state.json; it holds private test keys, so keep
it out of the repository). Needs the server to trust the conformance
certificate, like the suite's scoring checks.

    tools/second_phone.py --base-url https://<endpoint> account HANDLE PASSWORD
        a phone with a step-up key opens HANDLE (a full session); the approver
    tools/second_phone.py --base-url ... approve
        that phone lists approval requests and approves the newest (step-up)
    tools/second_phone.py --base-url ... signin HANDLE PASSWORD [elevated]
        a NEW phone holding an account of its own signs in to HANDLE; if the
        session is limited it asks for approval. "elevated": its scan has two
        mild findings (test-keys, no boot state: +40), a soft integrity cause an
        approval can accept (a failed probe cannot be approved, DESIGN.md 76)
    tools/second_phone.py --base-url ... relogin HANDLE PASSWORD [elevated]
        the same new phone signs in again (a new limited session and request)
    tools/second_phone.py --base-url ... complete
        the new phone completes its approved upgrade and makes a protected request
"""
import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conformance_suite as c  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument("--base-url", required=True)
parser.add_argument("--state", default="second_phone_state.json")
parser.add_argument("command", choices=("account", "approve", "signin", "relogin", "complete"))
parser.add_argument("args", nargs="*")
OPTIONS = parser.parse_args()
STATE = OPTIONS.state
api = c.Api(OPTIONS.base_url)


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def unpem(text):
    return serialization.load_pem_private_key(text.encode(), password=None)


def load():
    try:
        with open(STATE) as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


def save(state):
    with open(STATE, "w") as handle:
        json.dump(state, handle, indent=1)


def phone_from(entry):
    inst = c.Installation()
    inst.key = unpem(entry["key"])
    inst.installation_id = entry["installation_id"]
    inst.device_id = entry["device_id"]
    return inst


def factor():
    return c.live_settings(api).get("stepup_factor", "passcode")


def new_phone(with_stepup):
    inst = c.Installation()
    kwargs = {}
    stepup = None
    if with_stepup:
        stepup, jwk = c.stepup_jwk_pair()
        kwargs = {"stepup_public_key": jwk,
                  "stepup_key_auth": {"factor": factor(), "mode": "per_use", "window_seconds": 0}}
    st, pl = c.enrol(api, inst, c.fresh_hint(), **kwargs)
    assert st in (200, 201), (st, pl)
    token = c.device_token(api, inst)
    decision = c.submit_report(api, inst, token)
    print("scripted phone %s: integrity %s/%s" % (inst.installation_id[:8], decision["score"], decision["verdict"]))
    return inst, stepup, token


def show_session(label, pl):
    print("%s: scope=%s limited=%s routes=%s accepted=%s" % (
        label, pl.get("scope"), pl.get("limited_causes"), pl.get("upgrade_routes"),
        pl.get("accepted_causes")))


def main():
    command = OPTIONS.command
    argv = [None, None, command] + OPTIONS.args
    state = load()
    if command == "account":
        handle, password = argv[3], argv[4]
        inst, stepup, token = new_phone(with_stepup=True)
        st, pl = c.open_account(api, inst, token, handle, password)
        print("open account %s: %s %s" % (handle, st, c.error_code(pl) or ""))
        if st in (200, 201):
            show_session("approver phone", pl)
        state["approver"] = {"key": pem(inst.key), "stepup": pem(stepup),
                             "installation_id": inst.installation_id, "device_id": inst.device_id,
                             "access": pl.get("access_token"), "refresh": pl.get("refresh_token")}
        save(state)
    elif command == "approve":
        entry = state["approver"]
        inst = phone_from(entry)
        token = c.device_token(api, inst)
        c.submit_report(api, inst, token)
        # Access tokens live ten minutes; take the newest pair first.
        st, fresh = c._refresh(api, inst, entry["refresh"])
        if st == 200:
            entry["access"], entry["refresh"] = fresh["access_token"], fresh["refresh_token"]
            state["approver"] = entry
            save(state)
        st, listed = c.protected(api, inst, "GET", "/v1/auth/approvals", entry["access"])
        approvals = listed.get("approvals") or [] if st == 200 else []
        print("approver sees %d request(s): %s %s" % (len(approvals), st, c.error_code(listed) or ""))
        for item in approvals:
            print("  %s from %s" % (item["request_id"], item["requesting_installation"]))
        if approvals:
            rid = approvals[0]["request_id"]
            st, pl = c.stepup_call(api, inst, unpem(entry["stepup"]), "POST",
                                   "/v1/auth/approvals/%s/approve" % rid, entry["access"], {}, factor())
            print("approve %s: %s %s" % (rid, st, c.error_code(pl) or pl))
    elif command in ("signin", "relogin"):
        handle, password = argv[3], argv[4]
        # "elevated": the scripted phone's scan has two mild findings (+40), a
        # soft integrity cause of its own, so it is limited even where a DBA
        # gave extra accounts on a phone no points.
        elevated = len(argv) > 5 and argv[5] == "elevated"
        if command == "signin":
            # A phone that already holds one account of its own, as a second
            # person's phone would: two accounts on it (+35) plus the account's
            # second device (+35) plus a new phone (+10) is review, within counts.
            inst, _, token = new_phone(with_stepup=False)
            st, pl = c.open_account(api, inst, token, "own-" + c.secrets.token_hex(3), password)
            print("its own account first: %s %s" % (st, c.error_code(pl) or ""))
        else:
            inst = phone_from(state["newphone"])
            token = c.device_token(api, inst)
            c.submit_report(api, inst, token)
        if elevated:
            decision = c.submit_report(api, inst, token, c._elevate)
            print("scripted phone scan: %s/%s" % (decision["score"], decision["verdict"]))
        st, pl = c.sign_in(api, inst, token, handle, password)
        print("sign in %s on the scripted phone: %s %s" % (handle, st, c.error_code(pl) or ""))
        if st == 200:
            show_session("new phone", pl)
        entry = {"key": pem(inst.key), "installation_id": inst.installation_id,
                 "device_id": inst.device_id, "access": pl.get("access_token"),
                 "refresh": pl.get("refresh_token"), "elevated": elevated}
        if st == 200 and pl.get("scope") == "limited":
            st, req = c.protected(api, inst, "POST", "/v1/auth/upgrade/request", entry["access"],
                                  {"route": "approval"})
            print("approval request: %s %s %s" % (st, req.get("request_id"), c.error_code(req) or ""))
            entry["request_id"] = req.get("request_id")
        state["newphone"] = entry
        save(state)
    elif command == "complete":
        entry = state["newphone"]
        inst = phone_from(entry)
        token = c.device_token(api, inst)
        c.submit_report(api, inst, token, c._elevate if entry.get("elevated") else None)
        st, up = c.protected(api, inst, "POST", "/v1/auth/upgrade", entry["access"],
                             {"route": "approval", "request_id": entry.get("request_id")})
        print("complete upgrade: %s %s %s" % (st, c.error_code(up) or "", (up.get("error") or {}).get("details") or ""))
        if st == 200:
            show_session("new phone after upgrade", up)
            st, me = c.protected(api, inst, "GET", "/v1/account/me", up["access_token"])
            print("protected request after upgrade: %s %s" % (st, c.error_code(me) or "ok"))
    else:
        raise SystemExit("unknown command " + command)


if __name__ == "__main__":
    main()
