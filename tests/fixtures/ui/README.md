# SYNTHETIC — UI development fixture, not a recording

These files exist so the public UI can be designed against framework §13
scenarios 1–5 plus an analysis-limit case and a z3 veto case. They are not a
recorded run. `scripts/ui_preview.py` is the only consumer. Do not seed
`replay/`, Render, the Dockerfile or `pulseguard.api` from this directory.
