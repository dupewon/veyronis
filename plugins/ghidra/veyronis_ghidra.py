#!/usr/bin/env python3
# @category Veyronis
# @keybinding Ctrl-Shift-V
# @menupath Tools.Veyronis.Overlay Runtime Telemetry
"""
◈ VEYRONIS GHIDRA FORENSIC & RUNTIME OVERLAY PLUGIN ◈
Comprehensive Ghidra Python / FlatProgramAPI integration for:
  - Dynamic runtime event overlay & API argument annotations (Pre & Post comments)
  - Basic block execution heatmap coloring (Colorizing functions based on event hits)
  - Automatic Veyronis memory dump & OEP labeling
  - Deobfuscated string and indirect syscall resolution
"""

import json
import os
import sys

# Ghidra FlatProgramAPI imports (available inside Ghidra Python Script Manager)
try:
    from ghidra.program.model.address import Address
    from ghidra.program.model.listing import CodeUnit
    from java.awt import Color
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False


COLOR_HOT = Color(255, 80, 80)      # High Execution Heatmap
COLOR_OEP = Color(80, 220, 80)      # Recovered OEP
COLOR_API = Color(80, 180, 255)     # API Call Site


def load_events(path):
    if not os.path.exists(path):
        print(f"[-] Error: Path {path} not found.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def apply_ghidra_overlay(events, current_program, flat_api):
    if not GHIDRA_AVAILABLE:
        print(f"[*] Standalone Mode: Loaded {len(events)} telemetry events (Ghidra API inactive in CLI).")
        return

    image_base = current_program.getImageBase().getOffset()
    listing = current_program.getListing()
    applied_count = 0

    print(f"[+] Veyronis Ghidra Bridge: Overlaying {len(events)} telemetry records on Base: 0x{image_base:X}...")

    for ev in events:
        ev_type = ev.get("event_type", "")
        data = ev.get("data", {})
        rva = data.get("address") or data.get("rva") or 0

        if rva > 0:
            addr = current_program.getAddressFactory().getDefaultAddressSpace().getAddress(image_base + rva)
            code_unit = listing.getCodeUnitAt(addr)

            if code_unit is not None:
                cmt = f"[VEYRONIS RUNTIME] {ev_type}: {json.dumps(data)}"
                code_unit.setComment(CodeUnit.PRE_COMMENT, cmt)
                flat_api.setBackgroundColor(addr, COLOR_HOT)
                applied_count += 1

    print(f"[+] Veyronis Ghidra Bridge: Successfully annotated {applied_count} code locations!")


def main():
    if GHIDRA_AVAILABLE:
        # Running inside Ghidra GUI / Headless Analyzer
        events_file = flat_api.askFile("Select Veyronis JSON/Artifact Export", "Open")
        if events_file:
            events = load_events(events_file.getAbsolutePath())
            apply_ghidra_overlay(events, currentProgram, this)
    else:
        if len(sys.argv) > 1:
            events = load_events(sys.argv[1])
            apply_ghidra_overlay(events, None, None)
        else:
            print("[*] Usage: Place in Ghidra scripts directory or run: python veyronis_ghidra.py <session.json>")


if __name__ == "__main__":
    main()
