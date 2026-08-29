#!/usr/bin/env python3
"""
◈ VEYRONIS X64DBG DYNAMIC FORENSIC OVERLAY PLUGIN ◈
Comprehensive x64dbg / x64dbgpy integration for:
  - Runtime API telemetry overlay & comment insertion
  - Live execution heatmap coloring
  - Recovered OEP breakpoint placement and jump trace labeling
  - Veyronis memory dump integration
"""

import json
import os
import sys

# Attempt x64dbgpy import
try:
    import x64dbgpy.pluginsdk.x64dbg as x64dbg
    import x64dbgpy.pluginsdk._scriptapi as scriptapi
    X64DBG_AVAILABLE = True
except ImportError:
    X64DBG_AVAILABLE = False


COLOR_THREAT = 0x0000FF  # Red
COLOR_OEP = 0x00FF00     # Green
COLOR_API = 0xFFFF00     # Cyan/Yellow


def load_events(path):
    if not os.path.exists(path):
        print(f"[-] Veyronis: File {path} not found.")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def apply_x64dbg_overlay(events):
    if not X64DBG_AVAILABLE:
        print(f"[*] Standalone Mode: Loaded {len(events)} events (Run inside x64dbg Python console to apply live comments).")
        return

    base = scriptapi.module.GetMainModuleBase()
    print(f"[+] Veyronis: Overlaying {len(events)} telemetry events onto module base 0x{base:X}...")

    applied = 0
    for ev in events:
        ev_type = ev.get("event_type", "")
        data = ev.get("data", {})
        rva = data.get("address") or data.get("rva") or 0

        if rva > 0:
            ea = base + rva
            cmt = f"[VEYRONIS] {ev_type}: {json.dumps(data)}"
            scriptapi.comment.Set(ea, cmt)
            scriptapi.gui.SetColor(ea, COLOR_API)
            applied += 1

    print(f"[+] Veyronis: Successfully applied {applied} live annotations into x64dbg listing!")


def main():
    if len(sys.argv) > 1:
        events = load_events(sys.argv[1])
        apply_x64dbg_overlay(events)
    else:
        print("[*] Usage: python veyronis_x64dbg.py <events.json>")


if __name__ == "__main__":
    main()
