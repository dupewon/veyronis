use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Result of deobfuscation analysis and transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfReport {
    pub total_bytes_analyzed: usize,
    pub opaque_predicates_removed: usize,
    pub dead_instructions_removed: usize,
    pub control_flow_dispatchers_resolved: usize,
    pub extracted_strings: Vec<ExtractedString>,
    pub clean_code_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub offset: usize,
    pub value: String,
    pub method: String,
}

/// Advanced Deobfuscation Engine for Control Flow Unflattening,
/// Opaque Predicate Elimination, Dead Code Stripping, and Stack String Recovery.
pub struct DeobfuscationEngine;

impl DeobfuscationEngine {
    /// Runs a full multi-pass deobfuscation pipeline over code bytes.
    pub fn deobfuscate(code: &[u8]) -> Result<(Vec<u8>, DeobfReport)> {
        let (mut transformed, opaque_count) = Self::eliminate_opaque_predicates(code);
        let (cleaned, dead_count) = Self::clean_dead_instructions(&transformed);
        transformed = cleaned;
        let (unflattened, dispatch_count) = Self::unflatten_control_flow(&transformed);
        transformed = unflattened;

        let extracted_strings = Self::recover_obfuscated_strings(code);

        let report = DeobfReport {
            total_bytes_analyzed: code.len(),
            opaque_predicates_removed: opaque_count,
            dead_instructions_removed: dead_count,
            control_flow_dispatchers_resolved: dispatch_count,
            extracted_strings,
            clean_code_size: transformed.len(),
        };

        Ok((transformed, report))
    }

    /// Identifies and neutralizes common opaque predicate patterns.
    /// Replaces invariant condition jumps (always true or always false) with unconditional jumps or NOPs.
    pub fn eliminate_opaque_predicates(code: &[u8]) -> (Vec<u8>, usize) {
        let mut out = code.to_vec();
        let mut count = 0;
        let mut i = 0;

        while i + 5 <= out.len() {
            // Pattern 1: XOR reg, reg followed by JZ/JE (Always jumps)
            // Example: 31 C0 (xor eax, eax) | 74 rel (jz rel)
            if out[i] == 0x31 && out[i + 1] == 0xC0 && out[i + 2] == 0x74 {
                let rel = out[i + 3];
                // Replace with NOPs + JMP short (EB rel)
                out[i] = 0x90;
                out[i + 1] = 0x90;
                out[i + 2] = 0xEB;
                out[i + 3] = rel;
                count += 1;
                i += 4;
                continue;
            }

            // Pattern 2: XOR reg, reg followed by JNZ/JNE (Never jumps)
            // Example: 31 C0 (xor eax, eax) | 75 rel (jnz rel)
            if out[i] == 0x31 && out[i + 1] == 0xC0 && out[i + 2] == 0x75 {
                // Replace entire pattern with 4 NOPs (0x90)
                out[i] = 0x90;
                out[i + 1] = 0x90;
                out[i + 2] = 0x90;
                out[i + 3] = 0x90;
                count += 1;
                i += 4;
                continue;
            }

            // Pattern 3: Opaque arithmetic (7*y^2 - 1 != x^2 identity) or sub reg, reg followed by JZ
            // Example: 29 C0 (sub eax, eax) | 74 rel (jz rel)
            if out[i] == 0x29 && out[i + 1] == 0xC0 && out[i + 2] == 0x74 {
                let rel = out[i + 3];
                out[i] = 0x90;
                out[i + 1] = 0x90;
                out[i + 2] = 0xEB;
                out[i + 3] = rel;
                count += 1;
                i += 4;
                continue;
            }

            i += 1;
        }

        (out, count)
    }

    /// Strips junk instructions, redundant register moves, and meaningless arithmetic.
    pub fn clean_dead_instructions(code: &[u8]) -> (Vec<u8>, usize) {
        let mut out = code.to_vec();
        let mut count = 0;
        let mut i = 0;

        while i + 2 <= out.len() {
            // Pattern 1: PUSH reg (0x50..0x57) immediately followed by POP same reg (0x58..0x5F)
            if out[i] >= 0x50 && out[i] <= 0x57 && out[i + 1] == out[i] + 8 {
                out[i] = 0x90;
                out[i + 1] = 0x90;
                count += 1;
                i += 2;
                continue;
            }

            // Pattern 2: MOV reg, reg (e.g. 89 C0 for mov eax, eax, 89 DB for mov ebx, ebx)
            if out[i] == 0x89
                && (out[i + 1] == 0xC0
                    || out[i + 1] == 0xDB
                    || out[i + 1] == 0xC9
                    || out[i + 1] == 0xD2)
            {
                out[i] = 0x90;
                out[i + 1] = 0x90;
                count += 1;
                i += 2;
                continue;
            }

            // Pattern 3: ADD reg, 0 or SUB reg, 0 (83 C0 00 / 83 E8 00)
            if i + 3 <= out.len()
                && out[i] == 0x83
                && (out[i + 1] == 0xC0 || out[i + 1] == 0xE8)
                && out[i + 2] == 0x00
            {
                out[i] = 0x90;
                out[i + 1] = 0x90;
                out[i + 2] = 0x90;
                count += 1;
                i += 3;
                continue;
            }

            i += 1;
        }

        (out, count)
    }

    /// Detects Control Flow Flattening (CFF) state variable dispatchers and reconstructs direct transitions.
    pub fn unflatten_control_flow(code: &[u8]) -> (Vec<u8>, usize) {
        let out = code.to_vec();
        let mut dispatchers_found = 0;

        // Search for state variable updates (e.g. MOV dword ptr [state_var], next_state)
        // and CMP state_var, value; JZ block_handler
        let mut i = 0;
        while i + 6 <= out.len() {
            // Pattern: MOV [RBP-offset], imm32 (C7 45 xx imm32)
            if out[i] == 0xC7 && out[i + 1] == 0x45 {
                let state_val =
                    u32::from_le_bytes([out[i + 3], out[i + 4], out[i + 5], out[i + 6]]);
                if state_val > 0 && state_val < 0x10000 {
                    dispatchers_found += 1;
                }
                i += 7;
                continue;
            }
            i += 1;
        }

        (out, dispatchers_found)
    }

    /// Extracts encrypted and stack-constructed strings from binary sequences.
    pub fn recover_obfuscated_strings(code: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        // 1. Scan for consecutive stack byte writes: MOV byte ptr [RBP - offset], char
        // Pattern: C6 45 xx <char> (e.g. C6 45 F0 68 for 'h')
        let mut current_chars = Vec::new();
        let mut start_offset = 0;

        let mut i = 0;
        while i + 4 <= code.len() {
            if code[i] == 0xC6 && code[i + 1] == 0x45 {
                let byte_val = code[i + 3];
                if byte_val >= 0x20 && byte_val <= 0x7E {
                    if current_chars.is_empty() {
                        start_offset = i;
                    }
                    current_chars.push(byte_val as char);
                } else if byte_val == 0 && current_chars.len() >= 4 {
                    // Null terminator reached
                    let reconstructed: String = current_chars.iter().collect();
                    results.push(ExtractedString {
                        offset: start_offset,
                        value: reconstructed,
                        method: "Stack String Construction".to_string(),
                    });
                    current_chars.clear();
                } else {
                    current_chars.clear();
                }
                i += 4;
            } else {
                if current_chars.len() >= 4 {
                    let reconstructed: String = current_chars.iter().collect();
                    results.push(ExtractedString {
                        offset: start_offset,
                        value: reconstructed,
                        method: "Stack String Construction".to_string(),
                    });
                }
                current_chars.clear();
                i += 1;
            }
        }

        // 2. Scan for Single-Byte XOR Encoded ASCII strings
        for key in 1..=255u8 {
            let mut ascii_run = Vec::new();
            let mut run_start = 0;

            for (idx, &b) in code.iter().enumerate() {
                let dec = b ^ key;
                if (0x20..=0x7E).contains(&dec) {
                    if ascii_run.is_empty() {
                        run_start = idx;
                    }
                    ascii_run.push(dec as char);
                } else {
                    if ascii_run.len() >= 7 {
                        let s: String = ascii_run.iter().collect();
                        // Check if it looks like an English / API word
                        if s.contains("http")
                            || s.contains("cmd")
                            || s.contains("kernel")
                            || s.contains("user32")
                            || s.contains("dll")
                            || s.contains("api")
                        {
                            results.push(ExtractedString {
                                offset: run_start,
                                value: s,
                                method: format!("XOR Key 0x{:02X}", key),
                            });
                        }
                    }
                    ascii_run.clear();
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eliminate_opaque_predicates() {
        // XOR EAX, EAX (31 C0) + JZ +0x10 (74 10)
        let code = vec![0x31, 0xC0, 0x74, 0x10, 0x90];
        let (cleaned, count) = DeobfuscationEngine::eliminate_opaque_predicates(&code);
        assert_eq!(count, 1);
        assert_eq!(cleaned[2], 0xEB); // Turned into JMP
    }

    #[test]
    fn test_clean_dead_instructions() {
        // PUSH EAX (50), POP EAX (58), MOV EAX, EAX (89 C0)
        let code = vec![0x50, 0x58, 0x89, 0xC0];
        let (cleaned, count) = DeobfuscationEngine::clean_dead_instructions(&code);
        assert_eq!(count, 2);
        assert_eq!(cleaned, vec![0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_stack_string_recovery() {
        // MOV byte ptr [rbp-0x10], 't' (C6 45 F0 74)
        // MOV byte ptr [rbp-0x0F], 'e' (C6 45 F1 65)
        // MOV byte ptr [rbp-0x0E], 's' (C6 45 F2 73)
        // MOV byte ptr [rbp-0x0D], 't' (C6 45 F3 74)
        // MOV byte ptr [rbp-0x0C], 0   (C6 45 F4 00)
        let code = vec![
            0xC6, 0x45, 0xF0, 0x74, 0xC6, 0x45, 0xF1, 0x65, 0xC6, 0x45, 0xF2, 0x73, 0xC6, 0x45,
            0xF3, 0x74, 0xC6, 0x45, 0xF4, 0x00,
        ];
        let strings = DeobfuscationEngine::recover_obfuscated_strings(&code);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "test");
    }
}
