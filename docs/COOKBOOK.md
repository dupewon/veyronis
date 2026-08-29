# 📚 Veyronis Practical Cookbook & Hands-on Guide

This cookbook contains practical, battle-tested scenarios for analyzing obfuscated binaries, recovering memory dumps, devirtualizing VMProtect, and leveraging IDA Pro / Ghidra / AI integrations.

---

## 📑 Table of Contents
1. [Recipe 1: VMProtect 2.x/3.x Devirtualization & Unpacking](#recipe-1-vmprotect-2x3x-devirtualization--unpacking)
2. [Recipe 2: Converting Memory Dumps (.dmp) to Valid Executables (.exe)](#recipe-2-converting-memory-dumps-dmp-to-valid-executables-exe)
3. [Recipe 3: Deobfuscating Control Flow Flattening & Recovering Stack Strings](#recipe-3-deobfuscating-control-flow-flattening--recovering-stack-strings)
4. [Recipe 4: Hunting Heaven's Gate & Indirect Syscall Stubs](#recipe-4-hunting-heavens-gate--indirect-syscall-stubs)
5. [Recipe 5: Kernel Memory Multi-Module Dumping & IDA Pro Automation](#recipe-5-kernel-memory-multi-module-dumping--ida-pro-automation)
6. [Recipe 6: Exporting LLM Prompts & Automated Threat Response](#recipe-6-exporting-llm-prompts--automated-threat-response)

---

## Recipe 1: VMProtect 2.x/3.x Devirtualization & Unpacking

### Scenario
You have an x86/x64 executable protected with VMProtect containing encrypted bytecode sections (`.vmp0`, `.vmp1`) and obfuscated dispatchers.

### Steps
1. **Analyze virtualization profile:**
   ```bash
   veyronis vmp protected_sample.exe --devirtualize
   ```
2. **Unpack clean PE image:**
   ```bash
   veyronis vmp protected_sample.exe --unpack --output unpacked_clean.exe
   ```
3. **In-place patch VM stubs with native x86 machine code:**
   ```bash
   veyronis patch-vmp protected_sample.exe --output patched_sample.exe
   ```

---

## Recipe 2: Converting Memory Dumps (.dmp) to Valid Executables (.exe)

### Scenario
You dumped a suspicious process using Process Hacker, Task Manager, or Volatility, leaving you with unaligned memory pages in a `.dmp` file.

### Steps
1. **Reconstruct virtual sections back to raw file offsets:**
   ```bash
   veyronis dmp2pe memory_dump.dmp --output recovered_binary.exe --fix-iat
   ```
2. **Inspect reconstructed PE headers:**
   ```bash
   veyronis analyze recovered_binary.exe
   ```

---

## Recipe 3: Deobfuscating Control Flow Flattening & Recovering Stack Strings

### Scenario
A malware payload uses OLLVM / Tigress style switch-case state dispatchers, opaque predicates (`x * (x + 1) % 2 == 0`), and character-by-character stack strings.

### Steps
1. **Run automated deobfuscation engine:**
   ```bash
   veyronis deobfuscate obfuscated_sample.exe --output deobf_sample.exe
   ```
2. **Output:**
   - Opaque jump invariants are rewritten to NOP / unconditional jumps.
   - Redundant dead code (`MOV reg, reg`, `ADD reg, 0`) is stripped.
   - Recovered stack strings and XOR-encoded strings are printed to terminal.

---

## Recipe 4: Hunting Heaven's Gate & Indirect Syscall Stubs

### Scenario
An evasion payload switches from 32-bit to 64-bit segment (`0x33`) or invokes direct NT syscalls to bypass AV/EDR userland API hooks.

### Steps
1. **Scan for transitions and SSN mapping:**
   ```bash
   veyronis syscalls evasion_sample.exe
   ```
2. **Output:**
   - Displays offset of `push 0x33; call $+5; ... retf` Heaven's Gate.
   - Translates raw SSN numbers (`0x0018`, `0x0050`, `0x003A`) directly to `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`.

---

## Recipe 5: Kernel Memory Multi-Module Dumping & IDA Pro Automation

### Scenario
Target process is running with anti-debugging and you want to capture all in-memory DLLs and automatically annotate them inside IDA Pro.

### Steps
1. **Check Windows Test Signing & Driver Status:**
   ```bash
   veyronis testsign
   ```
2. **Deep Dump Target PID:**
   ```bash
   veyronis dump --pid <PID> --output-dir dump_results
   ```
3. **Load into IDA Pro:**
   - Open IDA Pro -> `File` -> `Script File...` -> select `dump_results/apply_veyronis_ida.py`.
   - All recovered OEPs, decrypted strings, and API arguments will be automatically colored and labeled in the IDA database.

---

## Recipe 6: Exporting LLM Prompts & Automated Threat Response

### Scenario
You recorded a runtime session (`incident.vyr`) and want to generate an executive report or ask ChatGPT/Claude to analyze the IOCs.

### Steps
1. **Generate LLM-Ready Markdown Prompt:**
   ```bash
   veyronis export incident.vyr --format prompt --output llm_context.md
   ```
2. **Launch Interactive Web Dashboard:**
   ```bash
   veyronis serve incident.vyr --port 8080
   ```
   - Open `http://127.0.0.1:8080` to explore the interactive timeline, process tree, and VQL console.
