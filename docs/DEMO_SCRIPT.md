# Three-minute judge demo

Public demo: [pulseguard-dufi.onrender.com](https://pulseguard-dufi.onrender.com).
The table totals 3:00, with roughly 300 spoken words and time for clicks.

## Recording readiness

On 31 October 2026, the public `/health` and `/api/mode` returned REPLAY with verified replay
integrity. `/api/cases` exposed one remediated SQL-injection case, `PG-78817274bf`, from recorded
run `recorded-20261031T012001-4192c0`, with no priority. The walkthrough below follows the local
static UI's control labels; this was an API/source check, not a completed browser rehearsal.
Warm the page before recording and check the badge and case count again.

**After S2 merge:** record the full four-scenario cut only once the deployed replay contains all
four cases and their backend results. Existing S2 UI panels alone are insufficient. The current
single-case deployment supports scenario 1 without the planned priority, verifier or counterfactual
results. If recording that build, describe the other scenarios as planned and do not narrate
missing outcomes as observed. No API keys should appear on screen.

## Timed screen and narration

| Time | What to click or show | What to say |
| --- | --- | --- |
| 0:00–0:20 | Open the public URL. Show **Security case board**, **REPLAY** badge and run label. | “Security teams need fewer ungrounded alerts and a defensible route to a fix. PulseGuard connects scanner evidence, model reasoning, patch tests and an approval trail. This is a recorded run, available to judges without credentials.” |
| 0:20–0:40 | Click the **flask-sqli-taint** case card. Scroll to **Adjudication** and the model name. | “Meta Muse Spark proposes the judgment and patch. This recording stores the provider's `muse-spark-1.3-contributor` calls for adjudicator and remediator, including structured-output and usage metadata. Replay makes no new model calls. The model proposes; deterministic gates decide what advances.” |
| 0:40–1:25 | **Scenario 1:** show **Hard Evidence Block**, source-to-sink lines, adjudication score, then **Patch and sandbox gate**. Point to parameter binding, `rescan_before: 1`, `rescan_after: 0` and `pytest_ok: true`. Show recorded human approval and click **Simulate approve**. **After S2 merge:** also show **Deterministic verification**, **Counterfactual consistency**, P0 **Blast radius** and manual policy tier. | “Request input reaches SQL execution. The evidence carries IDs the judgment cites. The proposed fix binds a query parameter. The stored sandbox report shows one finding before, zero after, and passing regression tests. A human approved the recorded bundle. This click only simulates another decision. [After S2 merge: The gateway-to-ledger path explains P0 and why policy retains a human.]” |
| 1:25–1:50 | **Scenario 2 — after S2 merge:** return to **Cases**, select the Trivy dependency case by scanner/rule and `requirements.txt`. Show the **RECORDED Trivy finding** notice, CVE/fixed version evidence, dependency patch, sandbox report and automatic policy/approval record. There is no required “auto-approve” button. | “The dependency case names a CVE and a scanner-reported fixed version. The patch is a deterministic version bump. [After S2 merge: Verified lower-priority work can receive automatic approval under policy.] Recorded scanner evidence stays labelled.” |
| 1:50–2:15 | **Scenario 3 — after S2 merge:** select the Bandit **B608** case in **false positive**, located in the integer-cast route. Show the `int()` sanitizer evidence, score below 0.3, no patch and **Run trace** event `FALSE_POSITIVE_DROPPED`. Distinguish it from the other B608 case by its location and evidence. | “Bandit flags SQL string construction, but this path first converts input to an integer. The sanitizer fact is counter-evidence. The case is dropped from remediation, while its reason and event remain auditable. No patch is needed merely to satisfy a pattern match.” |
| 2:15–2:40 | **Scenario 4 — after S2 merge:** select the quarantined case from `order_note.py`. Show suspected manipulation, **No adjudication available**, **No proposed patch**, and `FINDING_QUARANTINED` in **Run trace**. | “This comment tells an AI reviewer to dismiss the finding and skip approval. The guard treats it as manipulation. Quarantine stops the model and remediation path and preserves a human-review case. Code comments cannot grant approval.” |
| 2:40–3:00 | Click **Process & KPIs**, point to event-derived counts, then **Download event log CSV**. End on the mode badge and case board. | “The process view is computed from stored events: remediation time, dropped false positives, human versus automatic approvals and rework. The local Redpanda adapter adds an optional transport; Render retains the memory bus. The result is a reviewable bundle and evidence trail, with the mode always explicit.” |

## Presenter evidence and limits

The model identity comes from the recorded
[`model_calls.json`](../replay/runs/recorded-20261031T012001-4192c0/PG-78817274bf/model_calls.json),
with `opencode.ai` as the recorded endpoint host. Meta describes the Muse Spark family in its
[model introduction](https://ai.meta.com/blog/introducing-muse-spark-msl/). Do not claim a direct
Meta API endpoint, a team-trained model, unrecorded Skeptic calls, image-based topology extraction,
provider data-retention terms or measured accuracy absent from the shown artifacts.

The recorded SQL case includes a bundle in the repository; the current UI displays the patch and
sandbox report, not a bundle-download control. There is no LIVE run-start control in this build.
Replay approval is simulated. Redpanda runtime selection in the runner remains planned even when
`PG_BUS=redpanda` is set. Docker is not running on the development host, so do not present local
container execution as validated. End the recording at three minutes; omit this preparation text.
