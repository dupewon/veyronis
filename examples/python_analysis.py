#!/usr/bin/env python3
"""
Sample Python script demonstrating the Veyronis Python SDK.
"""

import sys
from pathlib import Path

# Add sdk to path
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk" / "python"))

from veyronis import open_artifact, VqlEngine

def main():
    artifact_path = Path(__file__).parent.parent / "fixture1.vyr"
    if not artifact_path.exists():
        print(f"Artifact {artifact_path} not found. Run 'veyronis record' first.")
        return

    print("Opening Veyronis Artifact:", artifact_path)
    artifact = open_artifact(str(artifact_path))

    is_valid = artifact.verify()
    print(f"Container Authenticity & Merkle Integrity: {'VALID' if is_valid else 'INVALID'}")

    vql = VqlEngine(artifact)
    processes = vql.find_processes()
    print(f"Found {len(processes)} recorded process events.")
    for p in processes:
        print(f"  PID: {p['pid']} | Process: {p['process']} | Summary: {p['summary']}")

if __name__ == "__main__":
    main()
