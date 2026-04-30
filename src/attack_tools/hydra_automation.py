import subprocess
import json
import re

class HydraAutomation:
    def __init__(self, target_ip, usernames_file, password, threads=5):
        self.target_ip = target_ip
        self.usernames_file = usernames_file
        self.password = password
        self.threads = threads

    def run_enumeration(self, output_file="data/results/hydra-execution-log.txt"):
        cmd = [
            "hydra",
            "-L", self.usernames_file,
            "-p", self.password,
            f"ssh://{self.target_ip}",
            "-t", str(self.threads),
            "-v", "-I",
            "-o", output_file
        ]
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        findings = {
            "command": ' '.join(cmd),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "successful_logins": self._parse_successes(result.stdout),
            "enum_supported": "does not support user enumeration" not in result.stdout
        }
        return findings

    def _parse_successes(self, output):
        # Hydra marks success with [22][ssh]
        return re.findall(r'\[22\]\[ssh\] host: \S+ login: (\S+)', output)
