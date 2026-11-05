# MIRAGE

Local-first phishing detection and threat intelligence for Windows. Work in progress: M0 (foundation), M1 (URL engine) and M2 (email and file inspection) are built; see CLAUDE.md for the current state.

- Project rules and architecture: [CLAUDE.md](CLAUDE.md)
- Current plan: [docs/milestones/M0.md](docs/milestones/M0.md)
- Decisions: [docs/DECISIONS.md](docs/DECISIONS.md)

## Quick start

```
python -m venv .venv
python tasks.py deps
python tasks.py sandbox
python tasks.py hooks
python tasks.py test
python tasks.py eval
```

Known limitations and what is still unverified: [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

See the Commands table in `CLAUDE.md` for all tasks.
