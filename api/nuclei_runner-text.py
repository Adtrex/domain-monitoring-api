import subprocess
import json
from pathlib import Path

# Path to Nuclei binary
NUCLEI_PATH = Path(__file__).resolve().parent.parent / "bin" / "nuclei.exe"  # Windows
# On Linux/Render, it might be: "/usr/local/bin/nuclei"

def run_nuclei_scan(target, templates=None, output_file=None):
    """
    Run Nuclei scan on a target.

    Args:
        target (str): The domain to scan.
        templates (list[str], optional): List of template names (e.g., ["ssl"]).
        output_file (str, optional): File to save results in JSONL format.

    Returns:
        list: Parsed JSON results.
    """
    # Build command
    cmd = [str(NUCLEI_PATH), "-u", target]

    if templates:
        # join templates as comma separated
        cmd += ["-t", ",".join(templates)]

    # JSONL output
    if output_file:
        cmd += ["-jsonl", "-o", output_file]
    else:
        cmd += ["-jsonl"]

    # Run the scan
    result = subprocess.run(cmd, capture_output=True, text=True)

    # If saving to file, read results from file
    if output_file:
        results = []
        with open(output_file, "r") as f:
            for line in f:
                results.append(json.loads(line))
        return results

    # Otherwise, parse stdout
    results = []
    for line in result.stdout.strip().splitlines():
        results.append(json.loads(line))
    return results
