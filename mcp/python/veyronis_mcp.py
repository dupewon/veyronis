#!/usr/bin/env python3
"""
VEYRONIS Python MCP (Model Context Protocol) Bridge
Exposes Veyronis DFIR & threat intelligence tools to any AI model (Ollama, Claude Desktop, OpenAI, LangChain, Cursor).
"""

import sys
import subprocess
import os

def run_mcp_bridge():
    veyronis_bin = os.getenv("VEYRONIS_BIN", "veyronis.exe" if sys.platform == "win32" else "veyronis")
    sys.stderr.write(f"[*] Starting VEYRONIS Python MCP Bridge via {veyronis_bin}...\n")
    
    proc = subprocess.Popen(
        [veyronis_bin, "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1
    )
    
    try:
        for line in sys.stdin:
            proc.stdin.write(line)
            proc.stdin.flush()
            out_line = proc.stdout.readline()
            if out_line:
                sys.stdout.write(out_line)
                sys.stdout.flush()
    except KeyboardInterrupt:
        proc.terminate()

if __name__ == "__main__":
    run_mcp_bridge()
