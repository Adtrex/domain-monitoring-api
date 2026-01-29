import subprocess
import json
import os
import platform
from pathlib import Path

# ==========================
# Nuclei path setup
# ==========================
BASE_DIR = Path(__file__).resolve().parent.parent
NUCLEI_FOLDER = BASE_DIR / "bin"

# Detect OS
system = platform.system().lower()
if system == "windows":
    NUCLEI_PATH = NUCLEI_FOLDER / "nuclei.exe"
else:
    NUCLEI_PATH = NUCLEI_FOLDER / "nuclei"

# Allow override via environment variable
NUCLEI_PATH = os.getenv("NUCLEI_PATH", str(NUCLEI_PATH))

# Check binary exists
if not os.path.exists(NUCLEI_PATH):
    raise FileNotFoundError(f"Nuclei not found at: {NUCLEI_PATH}")

# ==========================
# Nuclei scan runner
# ==========================
def run_nuclei_scan(target: str, templates: list = None):
    """
    Run nuclei scan on a target.
    
    Args:
        target (str): domain or IP
        templates (list, optional): list of template names (e.g., ["ssl", "cnvd"])
    
    Returns:
        list: JSON results from Nuclei
    """
    templates = templates or ["ssl"]
    results = []

    for template in templates:
        command = [
            NUCLEI_PATH,
            "-u", target,
            "-t", template,
            "-jsonl"  # output JSON lines
        ]

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            # Each line is a separate JSON object
            for line in proc.stdout.splitlines():
                if line.strip():
                    results.append(json.loads(line))
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Scan failed for template {template}: {e}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")

    return results

# ==========================
# Example usage
# ==========================
if __name__ == "__main__":
    target_domain = "example.com"
    scan_results = run_nuclei_scan(target_domain, templates=["ssl"])
    print(json.dumps(scan_results, indent=2))
