import paramiko

def test_ssh_connection(host, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password, timeout=5)
        ssh.close()
        return True, None
    except Exception as e:
        return False, str(e)

def stream_ssh_command(host, port, username, password, command, emit_fn):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password)

        _, stdout, stderr = ssh.exec_command(command)

        for line in iter(stdout.readline, ""):
            emit_fn(line.rstrip("\n"))

        for line in iter(stderr.readline, ""):
            emit_fn("[stderr] " + line.rstrip("\n"))

        ssh.close()
    except Exception as e:
        emit_fn("[error] " + str(e))
