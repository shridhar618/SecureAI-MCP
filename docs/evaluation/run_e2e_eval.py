"""End-to-end evaluation of SecureAI's governance pipeline through the real
/api/chat endpoint (threat detection -> role-scoped answer -> governance),
offline mode (no LLM), fresh database and a fresh user per scenario.

Usage: python run_e2e_eval.py <backend_dir> <out.json>
"""
import csv
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

BACKEND = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(BACKEND))
os.chdir(BACKEND)

tmp = tempfile.mkdtemp(prefix="secureai_eval_")
os.environ.update({
    "DATABASE_URL": f"sqlite:///{tmp}/eval.db",
    "SECRET_KEY": "eval-secret-key-at-least-32-characters-long",
    "JWT_SECRET_KEY": "eval-jwt-secret-key-at-least-32-characters",
    "AI_PROVIDER": "mock",
    "FACE_BACKEND": "test",
    "DEBUG": "0",
})
for key in ("GEMINI_API_KEY", "OPENAI_API_KEY"):
    os.environ.pop(key, None)

from werkzeug.security import generate_password_hash  # noqa: E402

from app import create_app, db  # noqa: E402
from app.models.role import Role  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import rate_limit  # noqa: E402

DECISIONS = ["ALLOWED", "WARNING", "RESTRICTED"]
RISKS = ["LOW", "MEDIUM", "HIGH"]
STATUS_TO_DECISION = {"allowed": "ALLOWED", "filtered": "WARNING", "blocked": "RESTRICTED"}


def load_sets():
    v1 = json.loads((BACKEND / "evaluation" / "eval_dataset.json").read_text())["scenarios"]
    v1 = [{"id": s["id"], "role": s["user_role"], "question": s["question"],
           "decision": s["expected_decision"], "risk": s["expected_risk"], "category": s.get("category", "")} for s in v1]
    with open(BACKEND / "evaluation" / "eval_set_v2.csv", newline="") as f:
        v2 = [{"id": int(r["id"]), "role": r["role"], "question": r["question"],
               "decision": r["expected_decision"], "risk": r["expected_risk"], "category": r["category"]}
              for r in csv.DictReader(f)]
    return {"v1_15": v1, "v2_50": v2}


def prf(labels, pairs):
    per = {}
    for lab in labels:
        tp = sum(e == lab and a == lab for e, a in pairs)
        fp = sum(e != lab and a == lab for e, a in pairs)
        fn = sum(e == lab and a != lab for e, a in pairs)
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        per[lab] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3), "support": tp + fn}
    present = [lab for lab in labels if per[lab]["support"] > 0]
    total = len(pairs)
    macro = {k: round(sum(per[lab][k] for lab in present) / len(present), 3) for k in ("precision", "recall", "f1")}
    weighted = {k: round(sum(per[lab][k] * per[lab]["support"] for lab in present) / total, 3)
                for k in ("precision", "recall", "f1")}
    cm = {e: {a: sum(x == e and y == a for x, y in pairs) for a in labels} for e in labels}
    return {"accuracy": round(sum(e == a for e, a in pairs) / total, 3), "macro_avg": macro,
            "weighted_avg": weighted, "per_label": per, "confusion_matrix": cm}


def main():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    counter = [0]

    def fresh_user(role_name):
        counter[0] += 1
        username = f"eval_{counter[0]}"
        with app.app_context():
            role = Role.query.filter_by(name=role_name).first()
            if role is None:
                role = next((r for r in Role.query.all() if r.name.lower() == role_name.lower()), None)
            db.session.add(User(username=username, email=f"{username}@eval.example", role=role_name.lower(),
                                role_id=role.id if role else None, password_hash=generate_password_hash("pw12345")))
            db.session.commit()
        rate_limit._attempts.clear()
        res = client.post("/api/auth/login", json={"username": username, "password": "pw12345"})
        assert res.status_code == 200, (role_name, res.get_json())
        return {"Authorization": f"Bearer {res.get_json()['token']}"}

    report = {}
    for name, scenarios in load_sets().items():
        dec_pairs, risk_pairs, lat, rows = [], [], [], []
        for s in scenarios:
            headers = fresh_user(s["role"])
            t0 = time.perf_counter()
            res = client.post("/api/chat", json={"message": s["question"]}, headers=headers)
            ms = (time.perf_counter() - t0) * 1000
            body = res.get_json() or {}
            if res.status_code == 403:
                # Role lacks use_ai_assistant: request refused before any answer (logged blocked / medium).
                dec, risk, note = "RESTRICTED", "MEDIUM", "403 no assistant access"
            else:
                assert res.status_code == 200, (s, res.status_code, body)
                dec = STATUS_TO_DECISION.get(body["status"], body["status"].upper())
                risk, note = body["risk_level"].upper(), ""
            dec_pairs.append((s["decision"], dec))
            risk_pairs.append((s["risk"], risk))
            lat.append(ms)
            rows.append({**s, "actual_decision": dec, "actual_risk": risk, "latency_ms": round(ms, 2), "note": note})
        lat_sorted = sorted(lat)
        report[name] = {
            "n": len(scenarios),
            "decision": prf(DECISIONS, dec_pairs),
            "risk": prf(RISKS, risk_pairs),
            "latency_ms": {"mean": round(statistics.mean(lat), 2), "median": round(statistics.median(lat), 2),
                           "p95": round(lat_sorted[min(len(lat) - 1, int(0.95 * len(lat)))], 2),
                           "max": round(lat_sorted[-1], 2)},
            "rows": rows,
        }
        r = report[name]
        print(name, "n=", r["n"], "| decision acc", r["decision"]["accuracy"], "macroF1", r["decision"]["macro_avg"]["f1"],
              "wF1", r["decision"]["weighted_avg"]["f1"], "| risk acc", r["risk"]["accuracy"],
              "macroF1", r["risk"]["macro_avg"]["f1"], "| latency ms median", r["latency_ms"]["median"],
              "p95", r["latency_ms"]["p95"])
    OUT.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
