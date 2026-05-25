# Systemd Units

## threat-intel-pcap-buffer.service

Rolling tcpdump capture buffer for incident response — preserves recent
traffic for forensic analysis when alerts fire.

Captures 60-second pcap files, retains the 5 most recent (5 min sliding window).
Filters out management ports (SSH, Postgres, Redis, FastAPI, Vite) to avoid
recording our own traffic.

### Install

```bash
sudo cp threat-intel-pcap-buffer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable threat-intel-pcap-buffer.service
sudo systemctl start threat-intel-pcap-buffer.service
```

### Verify

```bash
sudo systemctl status threat-intel-pcap-buffer.service
ls -lh /var/threat-intel/pcaps/
```
