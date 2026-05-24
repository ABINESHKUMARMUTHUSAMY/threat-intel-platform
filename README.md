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
## Progress

- [x] **Day 1** — AWS infra, IAM, Postgres + Redis + FastAPI scaffold ([v0.1-day1-foundation](../../releases/tag/v0.1-day1-foundation))
- [x] **Day 2** — Scapy capture, 5-tuple flow aggregation, attack scripts, pcap buffer ([v0.2-day2-capture](../../releases/tag/v0.2-day2-capture))
- [x] **Day 3** — ML detection: dual-model pipeline ([eval report](docs/eval-report.md), [v0.3-day3-detection](../../releases/tag/v0.3-day3-detection))
- [x] **Day 4** — Automated response: idempotent playbook engine, IP blocklist (iptables + TTL + expiry worker), host isolation (AWS SG swap via boto3), MTTC measured at 99.97% median reduction ([Appendix B](docs/eval-report.md#appendix-b--mean-time-to-contain-mttc-measurement), [v0.4-day4-response](../../releases/tag/v0.4-day4-response))
- [x] **Day 5** — Adversarial robustness test ([Appendix C](docs/eval-report.md#appendix-c--adversarial-robustness-measurement)) revealed model brittleness to attack tooling (wfuzz: 0/5 detection). Added Suricata signature-based detection as complementary layer ([Appendix D](docs/eval-report.md#appendix-d--dual-detector-comparison-ml--suricata), [v0.5-day5-suricata](../../releases/tag/v0.5-day5-suricata))
- [ ] Day 6 — Topology mapper, dashboard, polish
- [ ] Day 7 — Validation, demo video, final docs

## License

MIT
