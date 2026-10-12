import json
import re
import paramiko


def get_alerts_by_rules(host, ssh_port, username, password, rule_ids, minutes=3):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=ssh_port, username=username, password=password)

    _, stdout_time, _ = ssh.exec_command("date -u +%s")
    server_now_epoch = int(stdout_time.read().decode().strip())
    cutoff_epoch = server_now_epoch - (minutes * 60)

    cmd = f"echo '{password}' | sudo -S tail -n 2000 /var/ossec/logs/alerts/alerts.json 2>/dev/null"
    _, stdout, _ = ssh.exec_command(cmd)
    raw = stdout.read().decode("utf-8", errors="ignore")
    ssh.close()

    rule_ids_set = {str(r) for r in rule_ids}
    alerts = []

    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("[sudo]"):
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        rule_id = str(alert.get("rule", {}).get("id", ""))
        if rule_ids_set and rule_id not in rule_ids_set:
            continue

        ts_str = alert.get("timestamp", "")
        try:
            from datetime import datetime
            normalized = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', ts_str.replace("Z", "+00:00"))
            ts = datetime.fromisoformat(normalized)
            ts_epoch = int(ts.timestamp())
            if ts_epoch < cutoff_epoch:
                continue
        except (ValueError, AttributeError):
            pass

        alerts.append({
            "timestamp": ts_str[:19].replace("T", " "),
            "rule_id": rule_id,
            "rule_description": alert.get("rule", {}).get("description", ""),
            "rule_level": alert.get("rule", {}).get("level", 0),
            "agent": alert.get("agent", {}).get("name", ""),
            "full_log": (alert.get("full_log", "") or "")[:300],
        })

    return list(reversed(alerts))
