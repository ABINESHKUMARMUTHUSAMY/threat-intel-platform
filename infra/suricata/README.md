# Suricata configuration

Suricata is installed natively on the sensor (not in Docker).
This directory contains the custom rule file and config notes.

## Installation

```bash
sudo apt update && sudo apt install -y suricata
```

## Configuration changes from default `/etc/suricata/suricata.yaml`

1. **HOME_NET** — set to the project VPC:
```yaml
   vars:
     address-groups:
       HOME_NET: "[10.20.0.0/16]"
       EXTERNAL_NET: "!$HOME_NET"
```

2. **af-packet** — capture on ens5 with a single thread to limit CPU:
```yaml
   af-packet:
     - interface: ens5
       threads: 1
       cluster-id: 99
       cluster-type: cluster_flow
       defrag: yes
```

3. **rule-files** — append our custom rules:
```yaml
   rule-files:
     - suricata.rules
     - threat-intel-custom.rules
```

## Custom rules

Copy `threat-intel-custom.rules` to `/var/lib/suricata/rules/` and restart:

```bash
sudo cp threat-intel-custom.rules /var/lib/suricata/rules/
sudo systemctl restart suricata
```

## Validation

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Should report `Configuration provided was successfully loaded.`
