# MIRAGE

Local-first phishing detection and threat intelligence for Windows. Work in progress: milestone M0 (foundation).

- Project rules and architecture: [CLAUDE.md](CLAUDE.md)
- Current plan: [docs/milestones/M0.md](docs/milestones/M0.md)
- Decisions: [docs/DECISIONS.md](docs/DECISIONS.md)

## Quick start

```
python -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt
python tasks.py test
python tasks.py eval
```

See the Commands table in `CLAUDE.md` for all tasks.
