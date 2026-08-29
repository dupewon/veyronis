use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::Path;
use veyronis_format::VyrReader;
use veyronis_query::{Parser as VqlParser, QueryEngine};

/// Return codes for C-ABI FFI.
pub const VYR_OK: c_int = 0;
pub const VYR_ERR_INVALID_ARG: c_int = -1;
pub const VYR_ERR_CONTAINER_CORRUPT: c_int = -2;
pub const VYR_ERR_AUTH_FAILED: c_int = -3;
pub const VYR_ERR_QUERY_FAILED: c_int = -4;

/// Verifies container header, Merkle tree root, and Ed25519 signature.
/// Returns 0 (VYR_OK) on success, or negative error code.
///
/// # Safety
/// The caller must ensure that `path_c` is a valid, non-null, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn veyronis_verify_file(path_c: *const c_char) -> c_int {
    if path_c.is_null() {
        return VYR_ERR_INVALID_ARG;
    }

    let path_str = match CStr::from_ptr(path_c).to_str() {
        Ok(s) => s,
        Err(_) => return VYR_ERR_INVALID_ARG,
    };

    let reader = match VyrReader::open_file(Path::new(path_str)) {
        Ok(r) => r,
        Err(_) => return VYR_ERR_CONTAINER_CORRUPT,
    };

    match reader.verify_integrity_and_signature() {
        Ok(()) => VYR_OK,
        Err(_) => VYR_ERR_CONTAINER_CORRUPT,
    }
}

/// Executes a VQL query over an artifact (decrypted using passphrase).
/// Allocates and returns a null-terminated JSON string (must be freed with `veyronis_free_string`).
///
/// # Safety
/// The caller must ensure that `path_c` and `query_c` are valid null-terminated C strings,
/// and `out_json` is a valid pointer to a pointer that can receive the allocated string.
#[no_mangle]
pub unsafe extern "C" fn veyronis_query_json(
    path_c: *const c_char,
    passphrase_c: *const c_char,
    query_c: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    if path_c.is_null() || query_c.is_null() || out_json.is_null() {
        return VYR_ERR_INVALID_ARG;
    }

    let path_str = match CStr::from_ptr(path_c).to_str() {
        Ok(s) => s,
        Err(_) => return VYR_ERR_INVALID_ARG,
    };

    let query_str = match CStr::from_ptr(query_c).to_str() {
        Ok(s) => s,
        Err(_) => return VYR_ERR_INVALID_ARG,
    };

    let reader = match VyrReader::open_file(Path::new(path_str)) {
        Ok(r) => r,
        Err(_) => return VYR_ERR_CONTAINER_CORRUPT,
    };

    let passphrase_bytes = if !passphrase_c.is_null() {
        CStr::from_ptr(passphrase_c).to_bytes()
    } else {
        b""
    };

    let decrypted = match reader.decrypt_with_passphrase(passphrase_bytes) {
        Ok(d) => d,
        Err(_) => return VYR_ERR_AUTH_FAILED,
    };

    let query = match VqlParser::parse_str(query_str) {
        Ok(q) => q,
        Err(_) => return VYR_ERR_QUERY_FAILED,
    };

    let engine = QueryEngine::new(&decrypted.events, decrypted.graph.as_ref());
    let results = engine.execute(&query);

    let json_bytes = match serde_json::to_string(&results) {
        Ok(j) => j,
        Err(_) => return VYR_ERR_QUERY_FAILED,
    };

    let c_string = match CString::new(json_bytes) {
        Ok(cs) => cs,
        Err(_) => return VYR_ERR_QUERY_FAILED,
    };

    *out_json = c_string.into_raw();
    VYR_OK
}

/// Frees a string allocated by Veyronis FFI functions.
///
/// # Safety
/// The caller must ensure that `ptr` was allocated by a Veyronis FFI function, or is null.
#[no_mangle]
pub unsafe extern "C" fn veyronis_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}
