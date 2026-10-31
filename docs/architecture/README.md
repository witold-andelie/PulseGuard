# Demo architecture image

`landscape.png` is generated from `landscape.dot`; edit the DOT source, then render again.
The six services and six service edges retain the values in
`pulseguard/risk/topology.json`. Internet and its ingress arrow are diagram context,
explicitly excluded from service topology. All service ids and risk attributes appear
in the image. Blast-radius scores are prioritisation aids (framework section 15).

Render from the repository root with Graphviz 14.1.5:

```sh
dot -Tpng docs/architecture/landscape.dot -o docs/architecture/landscape.png
```

The DOT fixes layout direction, fonts, spacing and DPI. Byte reproducibility requires
the same Graphviz version, renderer and fonts. Re-render into a temporary file and
compare SHA-256 hashes before replacing the committed image.

`extract_topology(llm=client)` sends only the PNG and the topology prompt/schema.
It returns `topology`, `source`, `validation` and the actual response `model` (or the
configured model on a failed call). Model creation is explicit: there are no calls at
import, scoring, API boot or REPLAY load. Image requests accept PNG/JPEG signatures
and extensions and cap their combined raw bytes at 4 MiB. Unsupported vision responses
(400/404/422 mentioning image, vision or content type) become `VisionUnsupportedError`.
Every model, JSON, contract or agreement failure selects the hand-written fixture and
records a safe reason; provider messages and image data never enter validation metadata.

A sibling `.dot` is checked automatically when available; `dot_path=...` requires
that source to be readable and valid. With no DOT, structural checks still apply.
The cross-check reads the annotated DOT subset used here: quoted service ids, quoted
attributes, one explicit node/edge statement each. `topology="context"` excludes
context. `service_label`, `internet_facing`, `sensitivity`, and edge `privilege`
attributes are authoritative; ids, direction and all risk attributes must agree.
Validation reports matched/missing/extra/different counts and ids for nodes and edges.
The source is a deterministic cross-check, never model input or a replacement for
image extraction. Schema checks also require unique ids, known edge endpoints, finite
weights in [0, 1], an internet-facing node, and the scanned `order-api` service.

## Merge hook for the PoC/LIVE workstream

No graph or API wiring is included. `score_finding` accepts the extraction result
directly, or use `topology_from_result(result)` to construct a reusable `Topology`.
The default `score_finding(finding)` keeps the existing fixture payload unchanged.
An explicitly injected fallback retains `fixture="hand-written"` plus its validation
reason; an extraction has `source="extracted"` and `validation`, with no fixture label.

After importing `extract_topology`, the graph's `blast` node can opt in by adding this
keyword to its existing `score_finding` call when a client is configured:

```python
topology=extract_topology(llm=deps.llm, session=f"pg-{state['case_id']}-topology") if deps.llm else None,
```

The owning workstream should gate this on its LIVE topology option and may cache the
result once per run. Persist the validation summary with the blast-radius payload.
REPLAY should keep using its recorded payload and must never trigger extraction.
