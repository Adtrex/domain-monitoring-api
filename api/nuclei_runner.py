import os
import platform
import subprocess
import json
import urllib.request
import zipfile
import stat

BIN_DIR = os.path.join(os.path.dirname(__file__), "../bin")
os.makedirs(BIN_DIR, exist_ok=True)

IS_WINDOWS = platform.system() == "Windows"
NUCLEI_VERSION = "v3.7.0"
NUCLEI_ZIP_NAME = f"nuclei_3.7.0_{'windows_amd64' if IS_WINDOWS else 'linux_amd64'}.zip"
NUCLEI_PATH = os.path.join(BIN_DIR, "nuclei.exe" if IS_WINDOWS else "nuclei")

def download_nuclei():
    if os.path.exists(NUCLEI_PATH):
        return

    print(f"[INFO] Downloading Nuclei {NUCLEI_VERSION}...")
    url = f"https://github.com/projectdiscovery/nuclei/releases/download/{NUCLEI_VERSION}/{NUCLEI_ZIP_NAME}"
    zip_path = os.path.join(BIN_DIR, NUCLEI_ZIP_NAME)

    urllib.request.urlretrieve(url, zip_path)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(BIN_DIR)
    os.remove(zip_path)

    if not IS_WINDOWS:
        st = os.stat(NUCLEI_PATH)
        os.chmod(NUCLEI_PATH, st.st_mode | stat.S_IEXEC)
    print("[INFO] Nuclei ready!")

def run_nuclei_scan(target, templates=None):
    download_nuclei()
    templates = templates or ["ssl"]
    results = []

    if not os.path.exists(NUCLEI_PATH):
        raise FileNotFoundError(f"Nuclei binary not found at {NUCLEI_PATH}")

    for template in templates:
        command = [NUCLEI_PATH, "-u", target, "-t", template, "-jsonl"]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, check=False)

            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        results.append(data)
                    else:
                        print(f"[WARN] Skipping non-dict JSON line: {line}")
                except json.JSONDecodeError:
                    print(f"[ERROR] Failed to parse JSON line: {line}")

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Scan error for template '{template}': {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")

    return results
