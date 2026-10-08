# IPsecScope

AI-assisted IPsec VPN protocol analyzer and security assessment prototype, built for Smart India Hackathon 2026, Problem Statement 26160 (NTRO).

IPsecScope takes captured IPsec traffic (IKE and ESP), works out what it can from the wire, infers what is hidden by encryption, and produces a security assessment with findings and a report.

> **Status:** prototype. It covers a subset of the full problem statement (see [Not in this prototype](#not-in-this-prototype)).

---

## What it does

| Stage | What happens | Code |
|---|---|---|
| Ingest | Reads a pcap and splits it into IKE and ESP flows | `backend/app/ingest.py` |
| IKE parsing | Extracts observed parameters from IKE exchanges (proposals, transforms, exchange types) | `backend/app/ike.py`, `observed.py` |
| ESP analysis | Per-flow features from ESP packets (sizes, timing) | `backend/app/esp.py`, `traffic.py` |
| Inference | Estimates what the capture does not show directly, such as mode and PFS, using rules and a random forest for traffic class | `backend/app/inferred.py`, `mode_pfs.py`, `pfs.py` |
| Assessment | Applies the rule set to produce findings with severity | `backend/app/assess.py`, `backend/rules/rules.yaml` |
| Report | Builds an exportable report | `backend/app/report.py` |
| API | FastAPI service that exposes all of the above | `backend/app/main.py` |
| Dashboard | React frontend for upload, preloaded demo data and replayed sessions | `frontend_new/` |

---

## Repository layout

```
backend/        FastAPI app, rules, trained models, unit tests
frontend_new/   React dashboard
testbed/        Lab setup scripts and the capture matrix runner
eval/           Evaluation scripts
tests/          Integration tests
data/
  features/     Extracted feature tables
  labels/       Ground-truth labels for the captures
  reports/      Generated assessment reports
  g1/           Lab gate G1 outputs
  splits.csv    Train/test split
Makefile        Common tasks (for example: make eval)
```

The raw captures (`data/pcaps/`, about 2.4 GB) are **not** stored in this repository. See [Getting the pcaps](#getting-the-pcaps).

---

## Setup

### Requirements

- Python 3.10+ (TODO: confirm your version with `python3 --version`)
- Node.js 18+ and npm (TODO: confirm with `node --version`)
- Linux (developed and tested on Kali Linux)
- For regenerating captures: the lab tooling used by `testbed/` (TODO: list, for example strongSwan, FreeRADIUS, tcpdump)

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt     # TODO: confirm this file exists, otherwise list packages
```

### Frontend

```bash
cd frontend_new
npm install
```

---

## Running

### Backend API

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000     # TODO: confirm the command and port
```

`app/main_mock.py` is a mock backend (TODO: describe when to use it, for example frontend work without real data).

### Dashboard

```bash
cd frontend_new
npm run dev                                   # TODO: confirm the script name and port
```

Then open the URL printed by the dev server (TODO: for example http://localhost:5173).

### Data sources in the dashboard

| Mode | Description |
|---|---|
| Upload | Upload your own pcap for analysis |
| Preloaded demo | Analyze bundled example captures (TODO: state where they come from) |
| Live / replay sessions | Replay a capture as a live session (TODO: describe any real-live-capture support) |

---

## Tests and evaluation

```bash
make eval                 # TODO: describe what this runs and what it outputs
pytest backend/tests tests
```

---

## Getting the pcaps

The capture set has 172 pcaps (about 2.4 GB), named like `c1_email_r1.pcap`:

| Part of name | Meaning |
|---|---|
| `c1` ... `c8` | Lab configuration (TODO: briefly describe what differs, such as cipher suite, mode, PFS) |
| `email`, `ping`, `video`, `voip`, `web` | Traffic type generated through the tunnel |
| `r1` ... `r4` | Repeat run |

**Option 1: regenerate them** in the lab:

```bash
python3 testbed/run_matrix.py      # TODO: add required arguments and runtime
```

**Option 2: download them:** TODO add a Google Drive or GitHub Release link here, then place the files in `data/pcaps/`.

---

## Results

TODO: fill in measured numbers from your own `make eval` output. Do not guess them. A suggested table:

| Task | Metric | Result |
|---|---|---|
| Traffic type classification | Accuracy / macro-F1 | TODO |
| Mode inference | Accuracy | TODO |
| PFS inference | Accuracy | TODO |
| Assessment findings | Precision / recall against labels | TODO |

Evaluation uses the splits in `data/splits.csv`.

---

## Limitations

- Trained and evaluated on captures from one lab testbed only. Results may not carry over to real-world networks.
- Inference of encrypted details (such as mode, PFS and traffic class) is statistical, not a guarantee.
- TODO: add any limits you know of (vendor coverage, IKE versions supported, IPv6 coverage, capture size limits).

## Not in this prototype

TODO: list the parts of PS 26160 you have not built, for example live capture from real devices, multi-vendor support and full-scale ML.

---

## Security note

The pre-shared key `labpsk-change-me` in `testbed/g1.sh` and `testbed/g1v6.sh` is a **lab-only placeholder**. It protects nothing real. Do not reuse it, and replace it with your own key in any other setting.

## Context

Built for Smart India Hackathon 2026, PS 26160 (NTRO): AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework.

## License

TODO: choose a license (for example MIT) or state "All rights reserved".
