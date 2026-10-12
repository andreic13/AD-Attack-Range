from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit
from ssh_client import test_ssh_connection, stream_ssh_command
from config_manager import load_config, write_new_config
from attack_loader import get_all_attacks_list, get_attack_by_id, render_params_for_command
from vm_manager import revert_to_snapshot
from wazuh_client import get_alerts_by_rules
from datetime import datetime
import math

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading")

attack_runs = {}  # {attack_id: {output, params, timestamp}}

# ------------------------- HOME PAGE --------------------------
@app.route("/")
def index():
    return render_template("home.html")

# ------------------------- ATTACKS PAGE --------------------------
@app.route("/attacks")
def attacks_page():
    config = load_config()
    attacks = get_all_attacks_list()
    return render_template("attacks_page.html", config=config, attacks=attacks)

# -------------------------- ATTACKS --------------------------
# attack detail page — loads YAML by id and passes it to the template
@app.route("/attack/<attack_id>")
def attack(attack_id):
    atk = get_attack_by_id(attack_id)
    if atk is None:
        return "Attack not found", 404
    return render_template("attack.html", attack=atk)

# websocket event: receive attack id + user params, run steps sequentially on Kali
@socketio.on("run_attack")
def handle_run_attack(data):
    config = load_config()
    kali = config["kali"]
    atk = get_attack_by_id(data.get("attack_id"))
    params = data.get("params", {})

    if atk is None:
        emit("attack_output", {"line": "[error] Attack not found", "done": True})
        return

    run_id = data.get("attack_id")
    attack_runs[run_id] = {
        "output": [],
        "params": params,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    def send_line(line):
        attack_runs[run_id]["output"].append(line)
        emit("attack_output", {"line": line})

    for i, step in enumerate(atk.get("steps", []), start=1):
        command = render_params_for_command(step["command"], params)
        # trimite antet pentru pas, ca user să știe ce pas se execută
        emit("attack_output", {"line": f"-- Step {i}: {step['description']} --"})
        # execută comanda remote și trimite output linie cu linie în browser
        stream_ssh_command(
            kali["ip"], kali["port"],
            kali["username"], kali["password"],
            command, send_line
        )

    # anunță clientul că streaming-ul live e gata
    emit("attack_output", {"line": None, "done": True})

# -------------------------- FREE LAB --------------------------
# free lab page
@app.route("/free-lab")
def free_lab():
    return render_template("free-lab.html")

# websocket event: receive command "run_command" from browser, stream output line by line back
@socketio.on("run_command")
def handle_run_command(data):
    config = load_config() # apply current config for every request
    kali = config["kali"]
    command = data.get("command", "")

    def send_line(line): # emit function to call "output" event and send line by line
        emit("output", {"line": line})

    stream_ssh_command(
        kali["ip"], kali["port"],
        kali["username"], kali["password"],
        command, send_line
    )
    emit("output", {"done": True}) # signal to the browser that the command finished

# -------------------------- SETTINGS PAGE --------------------------
# settings page with current config values
@app.route("/settings", methods=["GET"])
def settings():
    config = load_config()
    return render_template("settings.html", config=config)

# save new config values from settings form
@app.route("/settings", methods=["POST"])
def save_settings():
    new_config = {
        "kali": {
            "ip": request.form.get("kali_ip"),
            "port": int(request.form.get("kali_port", 22)),
            "username": request.form.get("kali_username"),
            "password": request.form.get("kali_password")
        },
        "windows": {
            "ip": request.form.get("windows_ip"),
            "port": int(request.form.get("windows_port", 22)),
            "username": request.form.get("windows_username"),
            "password": request.form.get("windows_password")
        },
        "ubuntu_wazuh": {
            "ip": request.form.get("wazuh_ip"),
            "ssh_port": int(request.form.get("wazuh_ssh_port", 22)),
            "ssh_username": request.form.get("wazuh_ssh_username"),
            "ssh_password": request.form.get("wazuh_ssh_password")
        },
        "vmware": {
            "vmrun": request.form.get("vmrun_path"),
            "kali": {
                "vmx": request.form.get("vmx_kali"),
                "snapshot": request.form.get("snapshot_kali")
            },
            "windows": {
                "vmx": request.form.get("vmx_windows"),
                "snapshot": request.form.get("snapshot_windows")
            },
            "ubuntu_wazuh": {
                "vmx": request.form.get("vmx_wazuh"),
                "snapshot": request.form.get("snapshot_wazuh")
            }
        }
    }
    write_new_config(new_config) # overwrite config.json with new values
    return redirect(url_for("settings")) # redirect to url /settings with GET method

# -------------------------- REPORT --------------------------
@app.route("/report/<attack_id>")
def report(attack_id):
    atk = get_attack_by_id(attack_id)
    if atk is None:
        return "Attack not found", 404

    run = attack_runs.get(attack_id)
    if not run:
        return "No run data. Run the attack first.", 404

    attack_time = datetime.strptime(run["timestamp"], "%Y-%m-%d %H:%M:%S")
    minutes_since = max(1, math.ceil((datetime.now() - attack_time).total_seconds() / 60))

    alerts = []
    if "detection" in atk:
        config = load_config()
        w = config["ubuntu_wazuh"]
        rules = atk["detection"].get("wazuh_rules", [])
        rule_ids = [r["id"] if isinstance(r, dict) else r for r in rules]
        try:
            alerts = get_alerts_by_rules(
                w["ip"], w["ssh_port"], w["ssh_username"], w["ssh_password"],
                rule_ids, minutes_since
            )
        except Exception:
            alerts = []

    return render_template("report.html",
                           attack=atk,
                           output=run["output"],
                           params=run["params"],
                           timestamp=run["timestamp"],
                           alerts=alerts)

# -------------------------- WAZUH ALERTS --------------------------
@app.route("/wazuh/alerts/<attack_id>")
def wazuh_alerts(attack_id):
    atk = get_attack_by_id(attack_id)
    if not atk or "detection" not in atk:
        return jsonify({"alerts": [], "error": "No detection config for this attack"})

    config = load_config()
    w = config["ubuntu_wazuh"]
    rules = atk["detection"].get("wazuh_rules", [])
    rule_ids = [r["id"] if isinstance(r, dict) else r for r in rules]
    run = attack_runs.get(attack_id)
    if run:
        attack_time = datetime.strptime(run["timestamp"], "%Y-%m-%d %H:%M:%S")
        minutes = max(1, math.ceil((datetime.now() - attack_time).total_seconds() / 60))
    else:
        minutes = int(request.args.get("minutes", 3))

    try:
        alerts = get_alerts_by_rules(
            w["ip"], w["ssh_port"], w["ssh_username"], w["ssh_password"],
            rule_ids, minutes
        )
        return jsonify({"alerts": alerts})
    except Exception as e:
        return jsonify({"alerts": [], "error": str(e)})

# -------------------------- FREE LAB ALERTS --------------------------
@app.route("/wazuh/recent-alerts")
def wazuh_recent_alerts():
    config = load_config()
    w = config["ubuntu_wazuh"]
    minutes = int(request.args.get("minutes", 10))
    try:
        alerts = get_alerts_by_rules(
            w["ip"], w["ssh_port"], w["ssh_username"], w["ssh_password"],
            [], minutes
        )
        alerts = [a for a in alerts if "wazuh" not in a["agent"].lower()]
        return jsonify({"alerts": alerts})
    except Exception as e:
        return jsonify({"alerts": [], "error": str(e)})

# -------------------------- SNAPSHOT REVERT --------------------------
# revert a VM to its clean snapshot
@app.route("/revert/<machine>", methods=["POST"])
def revert(machine):
    if machine not in ("kali", "windows", "ubuntu_wazuh"):
        return jsonify({"ok": False, "error": "Unknown machine"})
    ok, err = revert_to_snapshot(machine)
    return jsonify({"ok": ok, "error": err})

# -------------------------- TEST CONNECTION --------------------------
# test SSH connection for each machine
@app.route("/test-connection", methods=["POST"])
def test_connection():
    data = request.get_json()
    creds = data.get("credentials")

    if creds:
        # if credentials are provided in the settings page, use them to test connection
        ip, port = creds.get("ip"), int(creds.get("port", 22))
        username, password = creds.get("username"), creds.get("password")
    else:
        # if the connection is tested from the home page, get the current config values for the selected machine
        config = load_config()
        machine = data.get("machine")
        if machine == "kali":
            m = config["kali"]
            ip, port, username, password = m["ip"], m["port"], m["username"], m["password"]
        elif machine == "windows":
            m = config["windows"]
            ip, port, username, password = m["ip"], m["port"], m["username"], m["password"]
        elif machine == "ubuntu_wazuh":
            m = config["ubuntu_wazuh"]
            ip, port, username, password = m["ip"], m["ssh_port"], m["ssh_username"], m["ssh_password"]
        else:
            return jsonify({"ok": False, "error": "Unknown machine"})

    ok, err = test_ssh_connection(ip, port, username, password)
    return jsonify({"ok": ok, "error": err})

if __name__ == "__main__":
    socketio.run(app, debug=True)
