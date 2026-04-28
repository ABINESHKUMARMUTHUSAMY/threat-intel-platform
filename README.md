# Network Threat Intelligence & Automated Response Platform

Real-time network threat monitoring with ML-based anomaly detection (XGBoost on CICIDS2017), automated incident response (host isolation, IP blocking, YARA rule generation), and topology mapping for unauthorized device detection.

**Status:** 🚧 In active development (Day 1 of 7)

## Architecture

![Architecture](docs/architecture.svg)

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Capture | Scapy (AsyncSniffer) |
| Message Bus | Redis Streams |
| Storage | PostgreSQL + TimescaleDB |
| ML | XGBoost, Isolation Forest, scikit-learn |
| Backend | FastAPI, Python 3.11 |
| Frontend | React + Vite, shadcn/ui, vis-network |
| Infra | AWS EC2, Docker Compose |

## Quickstart

_Coming Day 7_

## Evaluation

_Coming Day 7 — see [docs/eval-report.md](docs/eval-report.md)_

## License

MIT
