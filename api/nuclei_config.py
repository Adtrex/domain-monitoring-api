import os
from pathlib import Path
import subprocess

# ==========================================================
# Project paths
# ==========================================================
BASE_DIR = Path(__file__).resolve().parent.parent
NUCLEI_PATH = os.path.join(BASE_DIR, "bin", "nuclei.exe")


def get_nuclei_scanner():
    """
    Windows-safe PyNuclei initialization.
    Includes:
    - Absolute nuclei path
    - Subprocess fixes
    - Scan thread monkey-patch (WinError 2 fix)
    """

    # ------------------------------------------------------
    # Verify nuclei binary exists
    # ------------------------------------------------------
    if not os.path.exists(NUCLEI_PATH):
        raise FileNotFoundError(f"Nuclei not found at: {NUCLEI_PATH}")

    print(f"[INFO] Found Nuclei at: {NUCLEI_PATH}")

    # ------------------------------------------------------
    # Monkey patch PyNuclei checks (Windows fix)
    # ------------------------------------------------------
    import PyNuclei.PyNuclei as pn

    def patched_check(nucleiPath):
        try:
            result = subprocess.run(
                [nucleiPath, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False
            )
            return result.returncode == 0
        except Exception:
            return False

    pn.Nuclei.isNucleiInstalled = staticmethod(patched_check)

    # ------------------------------------------------------
    # Initialize scanner
    # ------------------------------------------------------
    from PyNuclei import Nuclei
    scanner = Nuclei(nucleiPath=NUCLEI_PATH)

    # 🔒 Force absolute path everywhere
    scanner.nucleiPath = NUCLEI_PATH

    # ------------------------------------------------------
    # 🔥 PATCH SCAN THREAD (THIS FIXES WinError 2)
    # ------------------------------------------------------
    _original_thread = pn.Nuclei._nucleiThread

    def patched_nuclei_thread(self, target, template, *args, **kwargs):
        command = [
            self.nucleiPath,   # 🔒 ABSOLUTE PATH
            "-u", target,
            "-t", template
        ]

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False
        )

        stdout, stderr = process.communicate()
        return stdout, stderr

    pn.Nuclei._nucleiThread = patched_nuclei_thread

    return scanner
