"""Live race on relationship admission, against a real database (DESIGN.md 76).

Review R2: a sign-in's risk decision reads the relationship counts in one
transaction and the link is written in a later one. Four sign-ins of one
account from four new phones, all decided before any link is written, each
see one device on the account and are each admitted -- five links, which no
single decision allowed. This forces exactly that interleaving with five
connections:

    decide x4 (each sees the account on one device)
    link   x4 at once (each in its own transaction, released by a barrier)

and reports how many links the account ends with. With the recheck under the
account and device row locks (_admit_link) the first link wins and the other
three answer relationship_changed: two links. Run it on each engine before
trusting a change to admission; --compare runs an older server file through
the same race first (one without _admit_link links all four).

    python3 tools/race_admission.py [--compare path/to/old_device_trust_server.py]

Uses the server's own environment (DB_ENGINE, DB_HOST, DB_USERNAME, ...,
DEVICE_ID_MASTER_SECRET). Each race runs on its own synthetic account, phones
and installations (registration_method 'race_test'). Nothing is deleted
afterwards: device-account links are permanent evidence and nothing in this
project removes one (owner rule, DESIGN.md 63.3) -- so run it against a TEST
database only.
"""
import argparse
import importlib.util
import os
import secrets
import sys
import threading
import uuid
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))
PHONES = 4


def load(path, name):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def race(module):
    def cursor(connection):
        return module._DialectCursor(connection.cursor())

    setup = module.DIALECT.connect()
    cur = cursor(setup)
    account = str(uuid.uuid4())
    cur.execute("INSERT INTO demo_accounts (account_id, handle_lookup, password_hash) "
                "VALUES (%s, %s, %s)", (account, secrets.token_hex(32), b"race-test"))
    phones = []
    for _ in range(PHONES + 1):
        device, installation = str(uuid.uuid4()), str(uuid.uuid4())
        cur.execute("INSERT INTO recognized_devices (device_id, platform) VALUES (%s, %s)",
                    (device, "android"))
        cur.execute("INSERT INTO app_installations (installation_id, device_id, key_algorithm, "
                    "public_key_jwk, key_thumbprint, registration_method, "
                    "registration_confidence) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (installation, device, "ES256",
                     module.DIALECT.json_param({"race_test": True}),
                     secrets.token_hex(32), "race_test", "synthetic"))
        phones.append((device, installation))
    setup.commit()
    first, rest = phones[0], phones[1:]
    module._link_device_account(cur, first[0], account, first[1])
    setup.commit()

    decisions = [
        module._evaluate_risk_policy("account_login", device, installation, account_id=account,
                                     account_link_pending=True, persist=False)
        for device, installation in rest
    ]
    barrier = threading.Barrier(len(rest))
    outcomes = [None] * len(rest)

    def sign_in(index):
        device, installation = rest[index]
        connection = module.DIALECT.connect()
        try:
            c = cursor(connection)
            barrier.wait(20)
            if hasattr(module, "_admit_link"):
                module._admit_link(c, device, account, decisions[index])
            module._link_device_account(c, device, account, installation)
            connection.commit()
            outcomes[index] = "linked"
        except module.ApiProblem as problem:
            connection.rollback()
            outcomes[index] = problem.code
        except Exception as error:  # noqa: BLE001 - this IS the observation
            connection.rollback()
            outcomes[index] = "%s: %s" % (type(error).__name__, str(error).splitlines()[0])
        finally:
            connection.close()

    threads = [threading.Thread(target=sign_in, args=(i,)) for i in range(len(rest))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    cur.execute("SELECT COUNT(*) FROM device_account_links WHERE account_id = %s", (account,))
    links = cur.fetchone()[0]
    setup.rollback()
    setup.close()
    seen = sorted({d["context"]["account_device_count"] for d in decisions})
    return outcomes, links, seen


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--compare", help="an older device_trust_server.py to race first")
    args = parser.parse_args()
    os.environ.setdefault("LOG_LEVEL", "CRITICAL")
    if args.compare:
        outcomes, links, seen = race(load(args.compare, "dts_compare"))
        print("compared file : decisions saw %s device(s); %s; links=%d" % (seen, outcomes, links))
    current = load(os.path.join(HERE, "..", "device_trust_server.py"), "dts_current")
    outcomes, links, seen = race(current)
    ok = (links == 2 and outcomes.count("linked") == 1
          and outcomes.count("relationship_changed") == PHONES - 1)
    print("this build    : decisions saw %s device(s); %s; links=%d  %s"
          % (seen, outcomes, links, "PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
