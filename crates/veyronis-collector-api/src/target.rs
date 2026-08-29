use std::collections::BTreeMap;
use std::path::PathBuf;

/// Target process execution profile for collection attachment.
#[derive(Debug, Clone)]
pub struct TargetProcess {
    pub pid: u32,
    pub executable_path: PathBuf,
    pub command_line: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub environment: BTreeMap<String, String>,
    pub start_time_nanos: u64,
}

impl TargetProcess {
    pub fn new(
        pid: u32,
        executable_path: impl Into<PathBuf>,
        command_line: Vec<String>,
        start_time_nanos: u64,
    ) -> Self {
        Self {
            pid,
            executable_path: executable_path.into(),
            command_line,
            working_directory: None,
            environment: BTreeMap::new(),
            start_time_nanos,
        }
    }
}
