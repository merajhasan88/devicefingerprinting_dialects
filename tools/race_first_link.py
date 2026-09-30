"""Live race on the first device-account link, against a real database (DESIGN.md 63).

Review F10: two first logins of the same account on the same device both see no
link; the loser's INSERT hits the primary key. On PostgreSQL that aborts the
loser's whole transaction, so the statement its caller runs next (the
refresh-session INSERT in login/register) failed. This forces exactly that
interleaving with two connections:

    A: link (UPDATE finds nothing, INSERT) ........ commit
    B:          link (UPDATE finds nothing, INSERT blocks on A's key) -> duplicate
    B:          the caller's next statement, then commit

and reports whether B's transaction survived. Run it on each engine before
trusting a change to _link_device_account; --compare runs an older server file
through the same race first.

    python3 tools/race_first_link.py [--compare path/to/old_device_trust_server.py]

Uses the server's own environment (DB_ENGINE, DB_HOST, DB_USERNAME, ...,
DEVICE_ID_MASTER_SECRET) and the newest app_installations row as the device.
It inserts one throwaway demo account per run and deletes it afterwards.
"""
import argparse
import importlib.util
import os
import secrets
import sys
import threading
import time
import uuid
from importlib.machinery import SourceFileLoader

HERE = os.path.dirname(os.path.abspath(__file__))


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
    cur.execute("SELECT installation_id, device_id FROM app_installations "
                "ORDER BY created_at DESC LIMIT 1")
    installation, device = [str(x) for x in cur.fetchone()]
    account = str(uuid.uuid4())
    cur.execute("INSERT INTO demo_accounts (account_id, handle_lookup, password_hash) "
                "VALUES (%s, %s, %s)", (account, secrets.token_hex(32), b"race-test"))
    setup.commit()

    winner, loser = module.DIALECT.connect(), module.DIALECT.connect()
    module._link_device_account(cursor(winner), device, account, installation)
    outcome = {}

    def lose():
        c = cursor(loser)
        try:
            module._link_device_account(c, device, account, installation)
            c.execute("SELECT 1")
            c.fetchone()
            loser.commit()
            outcome["loser"] = "transaction continued and committed"
        except Exception as error:  # noqa: BLE001 - this IS the observation
            outcome["loser"] = "%s: %s" % (type(error).__name__, str(error).splitlines()[0])
            loser.rollback()

    thread = threading.Thread(target=lose)
    thread.start()
    time.sleep(1.5)  # let the loser block on the winner's key
    winner.commit()
    thread.join(20)
    winner.close()
    loser.close()

    cur.execute("SELECT COUNT(*) FROM device_account_links WHERE account_id = %s", (account,))
    links = cur.fetchone()[0]
    cur.execute("DELETE FROM device_account_links WHERE account_id = %s", (account,))
    cur.execute("DELETE FROM demo_accounts WHERE account_id = %s", (account,))
    setup.commit()
    setup.close()
    return outcome.get("loser", "loser did not finish"), links


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--compare", help="an older device_trust_server.py to race first")
    args = parser.parse_args()
    os.environ.setdefault("LOG_LEVEL", "CRITICAL")
    current = load(os.path.join(HERE, "..", "device_trust_server.py"), "dts_current")
    failed = False
    if args.compare:
        result, links = race(load(args.compare, "dts_compare"))
        print("compared file : %s (links=%d)" % (result, links))
    result, links = race(current)
    ok = result.startswith("transaction continued") and links == 1
    print("this build    : %s (links=%d)  %s" % (result, links, "PASS" if ok else "FAIL"))
    failed = not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
