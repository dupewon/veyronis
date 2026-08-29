use std::sync::atomic::{AtomicU64, Ordering};

static VIRTUAL_TICK_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Anti-Anti-Debug & Time-Dilation Shim Engine.
pub struct VeyronisShim;

impl VeyronisShim {
    /// Spoofs `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` checks.
    #[inline]
    pub fn spoof_is_debugger_present() -> bool {
        false
    }

    /// Spoofs `NtQueryInformationProcess` (ProcessDebugPort / ProcessDebugFlags).
    #[inline]
    pub fn spoof_debug_port() -> usize {
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
}

// C-ABI Exports for dynamic injection shim
#[no_mangle]
pub extern "C" fn veyronis_shim_is_debugger_present() -> i32 {
    0
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

        VeyronisShim::advance_virtual_time(10_000);
        assert_eq!(VeyronisShim::get_virtual_elapsed_time(500), 10_500);
    }
}
