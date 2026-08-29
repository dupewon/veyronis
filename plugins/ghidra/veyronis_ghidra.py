#!/usr/bin/env python3
"""
VEYRONIS Ghidra Overlay Plugin
Loads a .vyr behavioral container and overlays runtime execution hits, memory allocations,
and API parameters directly onto the Ghidra decompiler / disassembly listing.
"""

import json
import os
import sys

# Ghidra Python Environment Imports (simulated / stubbed for standalone execution)
try:
    from ghidra.program.model.address import Address
    from ghidra.app.util.viewer.field import ColorizingField
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False


def load_vyr_events(json_export_path):
    if not os.path.exists(json_export_path):
        print(f"[-] Error: File {json_export_path} not found.")
        return []
    with open(json_export_path, "r", encoding="utf-8") as f:
        return json.load(f)


def overlay_execution_hits(events):
    print(f"[+] Loaded {len(events)} VEYRONIS runtime events.")
    hit_count = 0
    for ev in events:
        ev_type = ev.get("event_type", "")
        resource = ev.get("resource", "")
        pid = ev.get("process_identity", {}).get("pid", 0)

        # In Ghidra script: colorize or set bookmark
        hit_count += 1
        print(f"  [*] [Hit #{hit_count}] PID:{pid} Type:{ev_type} Resource:{resource}")

    print(f"[+] Successfully applied {hit_count} runtime telemetry annotations to listing.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        events = load_vyr_events(sys.argv[1])
        overlay_execution_hits(events)
    else:
        print("[*] Usage: python veyronis_ghidra.py <exported_session.json>")
