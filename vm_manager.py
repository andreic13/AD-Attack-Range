import subprocess
from config_manager import load_config

def _win_to_wsl_path(win_path):
    # convert Windows path (C:\foo\bar) to WSL path (/mnt/c/foo/bar)
    path = win_path.replace("\\", "/")
    if len(path) >= 2 and path[1] == ":":
        drive = path[0].lower()
        path = f"/mnt/{drive}{path[2:]}"
    return path

def revert_to_snapshot(machine):
    config = load_config()
    vmware = config["vmware"]

    vmrun_wsl = _win_to_wsl_path(vmware["vmrun"])
    vm = vmware[machine]

    result = subprocess.run(
        [vmrun_wsl, "revertToSnapshot", vm["vmx"], vm["snapshot"]],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "Unknown error"
        return False, error

    subprocess.run(
        [vmrun_wsl, "start", vm["vmx"], "nogui"],
        capture_output=True, text=True
    )

    return True, None
