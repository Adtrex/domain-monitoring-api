from .nuclei_runner import run_nuclei_scan

def test_simple_scan(scanner=None):
    print("\n=== Testing Simple Scan ===")
    choice = input("Run a test scan on example.com? (y/n): ").lower()

    if choice != "y":
        return True

    results = run_nuclei_scan("example.com", templates=["ssl"])
    print("✓ Scan completed!")
    print(f"Results: {results}")
    return True
