import os, time, signal, subprocess, sys
import requests

DB = "db.sqlite3"
BASE = "http://127.0.0.1:8000"


def wait_ready(base, timeout=30):
    for _ in range(timeout * 10):
        try:
            if requests.get(base + "/api/auth/login", timeout=1).status_code in (200, 405, 422):
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError("server did not start")


def main():
    if os.path.exists(DB):
        os.remove(DB)
    subprocess.run([sys.executable, "manage.py", "migrate", "-v", "0"],
                   check=True, capture_output=True)
    srv = subprocess.Popen([sys.executable, "manage.py", "runserver", "127.0.0.1:8000",
                            "--noreload"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    try:
        wait_ready(BASE)
        s = requests.Session()

        def call(name, method, path, json=None, headers=None, expect=200):
            r = s.request(method, BASE + path, json=json, headers=headers or {})
            ok = r.status_code == expect
            print(f"{'OK ' if ok else 'FAIL'} {name} -> {r.status_code}")
            if not ok:
                print("   body:", r.text[:300])
            return r

        # --- docs routes must be removed ---
        call("DOCS REMOVED /api/docs", "GET", "/api/docs", expect=404)
        call("DOCS REMOVED /api/_docs/swagger-ui.css", "GET",
             "/api/_docs/swagger-ui.css", expect=404)

        # --- login as OPERATOR (acts on behalf of subject user) ---
        r = call("LOGIN operator", "POST", "/api/auth/login",
                  json={"username": "ops", "password": "ops"})
        tok = r.json()["access_token"]
        H = {"Authorization": f"Bearer {tok}"}
        SUBJECT = "cust-1001"

        # --- create wallet (bulk provision EOAs for subject) ---
        r = call("CREATE WALLET", "POST", "/api/wallet/create",
                  json={"subject_user_id": SUBJECT}, headers=H)
        if r.status_code == 200:
            print("   addresses:", [a["deposit_address"] for a in r.json()["addresses"]])
        # idempotent re-call
        r2 = call("CREATE WALLET idempotent", "POST", "/api/wallet/create",
                   json={"subject_user_id": SUBJECT}, headers=H)
        if r.status_code == 200 and r2.status_code == 200:
            n1 = len(r.json()["addresses"]); n2 = len(r2.json()["addresses"])
            print("   ADDRESS COUNT SAME:", n1 == n2, f"({n1} vs {n2})")

        # --- single address EOA ---
        r = call("ADDR ETH (EOA)", "POST", "/api/wallet/address",
                  json={"subject_user_id": SUBJECT, "network": "ETH", "address_index": 0}, headers=H)
        r = call("ADDR TON (memo)", "POST", "/api/wallet/address",
                  json={"subject_user_id": SUBJECT, "network": "TON", "address_index": 0}, headers=H)

        # --- balance check + auto sweep ---
        r = call("BAL CHECK -> auto sweep", "POST", "/api/wallet/balance/check",
                  json={"subject_user_id": SUBJECT, "network": "ETH"}, headers=H)
        jid = r.json().get("sweep_job_id")
        if jid:
            call("SWEEP STATUS", "GET", f"/api/sweeps/{jid}", headers=H)

        # idempotency
        r2 = call("BAL CHECK again (idempotency)", "POST", "/api/wallet/balance/check",
                   json={"subject_user_id": SUBJECT, "network": "ETH"}, headers=H)
        if jid:
            print("   SAME JOB ID:", jid == r2.json().get("sweep_job_id"))

        # Fund the same BSC asset before withdrawal. The concrete confirmed
        # stub event is ingested into the authoritative ledger by this check.
        call("BAL CHECK BSC -> ledger credit", "POST", "/api/wallet/balance/check",
             json={"subject_user_id": SUBJECT, "network": "BSC"}, headers=H)

        # --- withdrawals (operator creates ON BEHALF OF funded subject) ---
        r = call("WD REQUEST", "POST", "/api/withdrawals/request",
                  json={"subject_user_id": SUBJECT, "network": "BSC",
                        "to_address": "0x0000000000000000000000000000000000000002",
                        "amount": 0.5,
                        "idempotency_key": "smoke-withdrawal-cust-1001-bsc-001"}, headers=H)
        wid = r.json().get("id")

        # operator may NOT approve (RBAC: admin-only)
        call("OPERATOR APPROVE (expect 403)", "POST", f"/api/withdrawals/{wid}/approve",
              json={"admin_notes": "x"}, headers=H, expect=403)

        # unauthenticated request must be rejected (security regression check)
        call("NO-AUTH chains (expect 401)", "GET", "/api/ops/chains", expect=401)

        ra = call("LOGIN admin", "POST", "/api/auth/login",
                   json={"username": "admin", "password": "admin"})
        atok = ra.json()["access_token"]; AH = {"Authorization": f"Bearer {atok}"}
        call("ADMIN APPROVE -> broadcast", "POST", f"/api/withdrawals/{wid}/approve",
              json={"admin_notes": "ok"}, headers=AH)
        call("WD STATUS after approval", "GET", f"/api/withdrawals/{wid}", headers=H)

        # --- audit ---
        import django
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mpc_exchange.settings")
        django.setup()
        from custody.models import AdminActionLog
        print("\nAUDIT ROWS:", AdminActionLog.objects.count())
        for a in AdminActionLog.objects.order_by("id"):
            print(" -", a.action_type, a.entity_type, a.entity_id, a.actor_id)
    finally:
        srv.send_signal(signal.SIGTERM)
        try:
            srv.wait(timeout=10)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    main()
