use thiserror::Error;

#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("failed to initialize collector: {0}")]
    InitializationFailed(String),

    #[error("failed to attach to target process (PID: {pid}): {reason}")]
    AttachFailed { pid: u32, reason: String },

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("telemetry buffer full: {dropped} events dropped")]
    BufferFull { dropped: usize },

    #[error("OS API error: {0}")]
    OsApiError(String),

    #[error("collector already running")]
    AlreadyRunning,

    #[error("collector not started")]
    NotStarted,
}
