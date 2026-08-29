use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static VIRTUAL_TICK_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Status of PEB/TEB and KUSER_SHARED_DATA stealth camouflage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthCamouflageState {
    pub peb_being_debugged_spoofed: bool,
    pub peb_nt_global_flag_spoofed: bool,
    pub process_heap_flags_spoofed: bool,
    pub kuser_shared_data_kd_spoofed: bool,
    pub rdtsc_time_dilation_active: bool,
    pub virtual_time_offset_ms: u64,
}

/// Anti-Anti-Debug, PEB/TEB Camouflage & Time-Dilation Shim Engine.
pub struct VeyronisShim;

impl VeyronisShim {
    /// Spoofs `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` checks.
    #[inline]
    pub fn spoof_is_debugger_present() -> bool {
        false
    }

    /// Spoofs `NtQueryInformationProcess` (ProcessDebugPort / ProcessDebugFlags / ProcessDebugObjectHandle).
    #[inline]
    pub fn spoof_debug_port() -> usize {
        0
    }

    /// Returns spoofed PEB `BeingDebugged` byte value (always 0).
    #[inline]
    pub fn spoof_peb_being_debugged() -> u8 {
        0
    }

    /// Returns spoofed PEB `NtGlobalFlag` dword value (always 0x00, clears FLG_HEAP_ENABLE_TAIL_CHECK etc.).
    #[inline]
    pub fn spoof_peb_nt_global_flag() -> u32 {
        0x00000000
    }

    /// Returns spoofed ProcessHeap Flags (0x02 = HEAP_GROWABLE, clears HEAP_TAIL_CHECKING_ENABLED).
    #[inline]
    pub fn spoof_process_heap_flags() -> (u32, u32) {
        // (Flags, ForceFlags) -> Standard non-debugged heap values
        (0x00000002, 0x00000000)
    }

    /// Returns spoofed `KUSER_SHARED_DATA` KdDebuggerEnabled byte (0x7FFE02D4 = 0).
    #[inline]
    pub fn spoof_kuser_shared_data_debugger() -> u8 {
        0
    }

    /// Dilates / speeds up time for sleep evasion (skips malware delay loops).
    pub fn advance_virtual_time(millis: u64) {
        VIRTUAL_TICK_OFFSET.fetch_add(millis, Ordering::SeqCst);
    }

    /// Returns virtualized elapsed time incorporating time-dilation acceleration.
    pub fn get_virtual_elapsed_time(real_millis: u64) -> u64 {
        real_millis + VIRTUAL_TICK_OFFSET.load(Ordering::SeqCst)
    }

    /// Dilates RDTSC cycles so anti-analysis CPU timing delta loops appear natural.
    pub fn spoof_rdtsc(real_tsc: u64, min_delta: u64) -> u64 {
        real_tsc.saturating_add(min_delta)
    }

    /// Returns the active stealth configuration status report.
    pub fn get_camouflage_state() -> StealthCamouflageState {
        StealthCamouflageState {
            peb_being_debugged_spoofed: true,
            peb_nt_global_flag_spoofed: true,
            process_heap_flags_spoofed: true,
            kuser_shared_data_kd_spoofed: true,
            rdtsc_time_dilation_active: VIRTUAL_TICK_OFFSET.load(Ordering::Relaxed) > 0,
            virtual_time_offset_ms: VIRTUAL_TICK_OFFSET.load(Ordering::Relaxed),
        }
    }
}

// C-ABI Exports for dynamic injection shim
#[no_mangle]
pub extern "C" fn veyronis_shim_is_debugger_present() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn veyronis_shim_get_peb_being_debugged() -> u8 {
    VeyronisShim::spoof_peb_being_debugged()
}

#[no_mangle]
pub extern "C" fn veyronis_shim_get_nt_global_flag() -> u32 {
    VeyronisShim::spoof_peb_nt_global_flag()
}

#[no_mangle]
pub extern "C" fn veyronis_shim_accelerate_time(millis: u64) {
    VeyronisShim::advance_virtual_time(millis);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim_spoofing() {
        assert!(!VeyronisShim::spoof_is_debugger_present());
        assert_eq!(VeyronisShim::spoof_debug_port(), 0);
        assert_eq!(VeyronisShim::spoof_peb_being_debugged(), 0);
        assert_eq!(VeyronisShim::spoof_peb_nt_global_flag(), 0);
        assert_eq!(VeyronisShim::spoof_kuser_shared_data_debugger(), 0);

        let (flags, force_flags) = VeyronisShim::spoof_process_heap_flags();
        assert_eq!(flags, 2);
        assert_eq!(force_flags, 0);

        VeyronisShim::advance_virtual_time(10_000);
        assert_eq!(VeyronisShim::get_virtual_elapsed_time(500), 10_500);

        let state = VeyronisShim::get_camouflage_state();
        assert!(state.peb_being_debugged_spoofed);
        assert!(state.rdtsc_time_dilation_active);
    }
}
