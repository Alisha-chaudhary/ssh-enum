import subprocess
import json

class MetasploitScanner:
    def __init__(self, target_ip, port=22):
        self.target_ip = target_ip
        self.port = port

    def run_ssh_enumuser_module(self, usernames_file="data/wordlists/common-usernames-50.txt"):
        # Write a temporary resource script that msfconsole will run
        rc_script = f"""
use auxiliary/scanner/ssh/ssh_enumuser
set RHOSTS {self.target_ip}
set RPORT {self.port}
set USER_FILE {usernames_file}
set THRESHOLD 10
run
exit
"""
        with open("/tmp/msf_enum.rc", "w") as f:
            f.write(rc_script)

        cmd = ["msfconsole", "-q", "-r", "/tmp/msf_enum.rc"]
        print("Launching Metasploit...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        verdict = {
            "output": result.stdout,
            "hardening_detected": "hardened" in result.stdout.lower() or
                                  "not vulnerable" in result.stdout.lower(),
            "users_found": []
        }
        # Parse any found users
        for line in result.stdout.splitlines():
            if "exists" in line.lower():
                verdict["users_found"].append(line.strip())

        with open("data/results/metasploit-output.json", "w") as f:
            json.dump(verdict, f, indent=2)
        return verdict
