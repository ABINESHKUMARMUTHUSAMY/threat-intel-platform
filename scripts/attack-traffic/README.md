# Attack Traffic Generation Scripts

Run these from the attacker EC2 against the sensor's private IP.

## Setup (on attacker)

```bash
# These tools should already be installed from Day 2 setup
sudo apt update
sudo apt install -y nmap hping3 hydra slowhttptest curl
```

## Individual attacks

| Script | Attack type | CICIDS2017 label |
|--------|-------------|------------------|
| `port-scan.sh` | TCP port scan | PortScan |
| `syn-flood.sh` | SYN flood DoS | DoS Hulk / DoS GoldenEye |
| `ssh-bruteforce.sh` | SSH credential brute force | SSH-Patator |
| `slow-http.sh` | Slowloris-style DoS | DoS slowloris / Slowhttptest |
| `benign-traffic.sh` | Normal HTTP traffic | BENIGN |

## Full suite

```bash
./run-all-attacks.sh <sensor-private-ip>
```

Runs all 5 phases over ~5 minutes. Used for end-to-end validation.
