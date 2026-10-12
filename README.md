# AD Attack Range

A self-contained lab platform for simulating, running, and detecting misconfiguration-based attacks against Active Directory — orchestrated through a web UI, executed on a Kali VM, and monitored through Wazuh.

> Full technical write-up, environment setup, and detailed attack documentation: see [`texts/instructions_en.md`](texts/instructions_en.md).

## What it does

Instead of exploiting CVEs, every attack in this range abuses **legitimate Windows/AD functionality configured insecurely** — the kind of misconfigurations that show up constantly in real enterprise environments:

- **AS-REP Roasting** — Kerberos preauthentication disabled on an account
- **Kerberoasting** — service account with SPN + weak static password
- **Password Spraying** — weak password policy / permissive lockout
- **DCSync** — excessive replication rights via Domain Admins membership
- **Pass-the-Hash** — NTLM authentication using a captured/replicated hash

Each attack is defined, end-to-end, through a single YAML file: description, MITRE ATT&CK ID, misconfiguration, parameters, execution steps, and the Wazuh rule IDs expected to fire.

## Architecture

```
[Flask UI] → [Controller] → SSH → [Kali] → [Windows AD] → logs → [Wazuh] → [Flask UI]
```

- **Flask + Flask-SocketIO** web UI, with live (line-by-line) command/attack output over WebSockets
- **SSH (paramiko)** connection from the controller to Kali for executing attack commands
- **Wazuh** SIEM for log collection and detection, queried over SSH after each run
- **VMware `vmrun.exe`** integration to revert any VM to a clean snapshot if an attack leaves side effects (e.g. account lockouts)

## Features

- Plug-and-play attack catalog — drop a new YAML into `attacks/` and it's automatically picked up by the UI
- Live output streaming for both predefined attacks and an arbitrary-command "Free Lab" terminal
- Per-attack Wazuh alert lookup, filtered by rule ID and a time window anchored to the attack run
- Auto-generated, printable reports (attack info, parameters, output, alerts)
- One-click revert to a clean VM snapshot

## Project structure

```
.
├── app.py                # Flask + SocketIO app
├── config_manager.py     # read/write JSON config
├── ssh_client.py         # SSH client for Kali
├── attack_loader.py      # load/parameterize attacks from YAML
├── vm_manager.py         # revert to clean snapshot (vmrun.exe)
├── wazuh_client.py       # fetch and filter Wazuh alerts
├── config.json           # VM config (IPs, credentials)
├── templates/             # index, settings, free-lab, attack, report pages
├── static/                 # CSS, socket.io.min.js
└── attacks/                 # one YAML per attack
```

## Requirements

- VMware Workstation Pro
- A Windows Server VM configured as an AD Domain Controller
- A Kali Linux VM (SSH enabled)
- An Ubuntu VM running Wazuh

Full setup instructions (network config, AD setup, Wazuh install, audit policy) are in [`texts/instructions_en.md`](texts/instructions_en.md).

## Quick start

```bash
# 1. make sure the Kali, Windows and Wazuh VMs are running
# 2. verify SSH is up on Kali
sudo systemctl status ssh

# 3. from the controller machine
source venv/bin/activate
python app.py

# 4. open the UI
http://127.0.0.1:5000
```

## Disclaimer

This is an isolated lab environment built for studying attack techniques and the limits of default detection. It is not intended for use outside a controlled, authorized environment.
