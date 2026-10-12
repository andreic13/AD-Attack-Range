# Virtual infrastructure for simulating and analyzing misconfiguration-based attacks on Active Directory

## Purpose

This platform demonstrates how classic misconfigurations in a modern Active Directory infrastructure (Windows Server 2019) can be exploited using well-known attack techniques.

It does not rely on CVE-type vulnerabilities or outdated software, but on the abuse of legitimate Windows protocols/services that are configured insecurely — realistic scenarios frequently found in enterprise environments.

| Misconfiguration | Technique | Remediation |
|---|---|---|
| Kerberos preauthentication disabled | AS-REP Roasting | Enable preauthentication for all accounts |
| Service account with SPN + weak password | Kerberoasting | Strong passwords / gMSA / monitor ticket requests |
| NTLM fallback allowed | Relay / capture / downgrade attacks | Restrict NTLM via GPO |
| Weak password policy, no strict lockout | Password Spraying | Strict policy + lower threshold + monitoring |
| Excessive permissions in AD ACLs | ACL Abuse / Privilege Escalation | Audit and tighten delegations |
| Incomplete audit policy | Attacks go undetected | Enable advanced auditing + SIEM integration |

## Required resources

- Laptop/PC: minimum 8GB RAM, 100GB storage
- VMware Workstation Pro 17.6.2
- Windows Server 2019 VM (Domain Controller)
- Kali Linux VM (latest)
- Ubuntu 24.04.2 LTS VM (Wazuh Server)

## Environment setup

### 1. Windows Server 2019 + Active Directory
- Domain Controller: `DC01`, domain `corp.local`
- OUs: `Corp_Users`, `Corp_IT`, `Corp_ServiceAccounts`, `Corp_Servers`
- Regular users cannot log in directly on the DC (best practice)
- Minimum audit logging required for detection:
  ```
  auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
  auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
  auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
  ```

### 2. Ubuntu + Wazuh (SIEM)
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
To enable the services on boot:
```bash
sudo systemctl enable wazuh-manager
sudo systemctl enable wazuh-indexer
sudo systemctl enable wazuh-dashboard
```
A Wazuh agent is also installed on the Windows Server machine (starts automatically).

### 3. Kali Linux
Standard VM, used as the attack host.

### 4. Virtual network
All VMs on the same NAT subnet (VMware Virtual Network Editor), DHCP disabled, static IPs:

| VM | IP | Subnet mask | Gateway |
|---|---|---|---|
| Windows | 10.10.128.2 | 255.255.0.0 | 10.10.1.250 |
| Ubuntu | 10.10.128.3 | 255.255.0.0 | 10.10.1.250 |
| Kali | 10.10.128.4 | 255.255.0.0 | 10.10.1.250 |

ICMP enabled on Windows Firewall to test connectivity between VMs.

## Platform architecture

```
[Flask UI] → [Controller] → SSH → [Kali] → [Windows AD] → logs → [Wazuh] → [Flask UI]
```

- Flask UI + Flask-SocketIO (live output streaming instead of request/response)
- Communication with Kali over SSH (`ssh_client.py`, paramiko)
- Communication with Wazuh by reading logs over SSH
- Catalog of predefined attacks, each described in a YAML file (`attacks/*.yml`): name, description, scripts, parameters, steps, detection rules
- `vm_manager.py`: automatic revert to a clean snapshot (`vmrun.exe`) for any VM, in case something breaks

### Project structure

```
.
├── app.py                # Flask + SocketIO logic
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

## Running the platform

1. Start the Kali, Windows Server, and Ubuntu VMs
2. Verify SSH is running on Kali: `sudo systemctl status ssh`
3. Activate the app's virtualenv and run `python app.py`
4. Open `http://127.0.0.1:5000`

## Command/attack flow (SocketIO)

- `run_command` → runs an arbitrary command on Kali over SSH, output streamed line by line via the `output` event
- `run_attack` → loads the attack's YAML by `attack_id`, substitutes parameters into each step, runs them sequentially on Kali, streams output via `attack_output`, and signals `done: true` when finished

## Implemented attacks

| Attack | MITRE | Run limit |
|---|---|---|
| AS-REP Roasting | T1558.004 | unlimited (passive) |
| Kerberoasting | T1558.003 | unlimited (passive) |
| Password Spraying | T1110.003 | limited by lockout policy — requires unlocking accounts afterward |
| DCSync | T1003.006 | unlimited |
| Pass-the-Hash | T1550.002 | unlimited |

Each attack exploits a misconfiguration deliberately applied to the test accounts (disabled preauth, SPNs on service accounts, weak shared passwords, a privileged account with replication rights).

## Monitoring (Wazuh)

- Alerts are filtered by attack-specific `rule IDs` (from each YAML) and by a time window starting at attack execution
- Key observations from testing:
  - **AS-REP Roasting** and **DCSync** are largely invisible to default monitoring — detection requires enabling Advanced Audit Policy categories that are disabled by default
  - **Kerberoasting**, when run against an IP (rather than a hostname), triggers an NTLM fallback and shows up as "possible pass-the-hash" — Wazuh cannot distinguish between the two without extra context
  - Background alerts (`Logon Success`, `User Logoff`) occur constantly from normal AD traffic and are filtered out via rule ID + time window

## Reports

A report can be generated for each completed attack run (`/report/<attack_id>`), containing: attack details, parameters used, captured output, and the corresponding Wazuh alerts. Export to PDF is available via browser print.

## Disclaimer

Isolated lab environment, intended solely for studying attack techniques and detection limitations. Not to be used outside a controlled and authorized environment.
