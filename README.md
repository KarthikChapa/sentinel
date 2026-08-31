# Sentinel-IAM

**Cloud IAM Least-Privilege Auto-Remediation with Human-in-the-Loop Gateway**

Built for the micro1 Frontier Engineering Challenge.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # all optional; mock mode needs only stdlib
cp .env.example .env              # optional: fill in keys for live/slack mode

python scripts/generate_data.py   # generate the 11 synthetic scenarios
python evaluator.py               # run baseline + advanced, dump traces + metrics
```

## Outputs

- `trajectories.jsonl` — full agent trajectory traces (submission artifact)
- `results/metrics.json` — scored metrics table
- Printed baseline vs advanced comparison

See `docs/` for DEMO.md, REQUIREMENTS.md, CHANGELOG.md, REPRODUCTION.md.
