# Governance pipeline evaluation (paper figures)

Generated 2026-11-19 against `main` (commit 9aae926).

## Method

Each labelled scenario is sent as a chat message through the real `/api/chat`
endpoint (threat detection → role-scoped answer → governance engine), using a
fresh database and a fresh user of the scenario's role, so cumulative-risk
state never carries over between scenarios. No LLM is configured (offline
policy mode), so the results are deterministic. A role without the
`use_ai_assistant` permission (Guest) receives HTTP 403; this is scored as
RESTRICTED / MEDIUM, matching what the audit log records.

| Set | Source | Scenarios |
|---|---|---|
| A | `backend/evaluation/eval_dataset.json` | 15 |
| B | `backend/evaluation/eval_set_v2.csv` (paraphrase-heavy, all roles) | 50 |

Reproduce from `backend/`:

```
python ../docs/evaluation/run_e2e_eval.py . ../docs/evaluation/e2e_results.json
python ../docs/evaluation/make_figures.py ../docs/evaluation/e2e_results.json ../docs/evaluation/figures
```

## Results

| Metric | Set A (n = 15) | Set B (n = 50) |
|---|---|---|
| Decision accuracy | 0.87 | 0.66 |
| Decision macro-F1 | 0.60 | 0.46 |
| Decision weighted-F1 | 0.81 | 0.67 |
| Risk-level accuracy | 0.93 | 0.62 |
| Risk-level macro-F1 | 0.64 | 0.51 |
| Median latency | 9.5 ms | 7.1 ms |
| p95 latency | 27.2 ms | 11.4 ms |

## Suggested captions

- **Figure 1.** Classification performance of the SecureAI governance pipeline on the two labelled scenario sets. Set B uses paraphrased requests across all roles.
- **Figure 2.** Per-class precision, recall and F1-score of the governance decision on Set B (n = 50). The WARNING class has only two samples.
- **Figure 3.** Confusion matrices for Set B: (a) governance decision, (b) risk level. Rows are expected labels, columns are predicted labels.
- **Figure 4.** End-to-end latency of `/api/chat` per request in offline mode (no LLM call). Each dot is one scenario; boxes show the interquartile range.

## Notes for the discussion section

- Most Set B errors are false negatives on paraphrased sensitive requests (9 of 27 RESTRICTED scenarios were ALLOWED): salary asked as "take home", "wages" or "earn"; credentials as "SSH key" or "AWS access keys"; addresses as "where do they live". The rule-based detector matches keywords, so paraphrase coverage is its main limitation.
- Two Set B labels predate the current Access Control Policy (EV-SEC-003), which denies Guests the assistant: scenarios 1 and 6 expect ALLOWED but the system correctly refuses with 403.
- Macro-F1 is pulled down by the WARNING and MEDIUM classes, which have only two samples each in Set B.
- Latency excludes LLM generation. Set A's slowest request (about 27 ms) is the first one after start-up (cold start). Latency varies by a millisecond or two between runs; accuracy figures are identical on every run.
