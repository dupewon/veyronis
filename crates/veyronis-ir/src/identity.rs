use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique composite identity for an operating system process.
/// Prevents PID recycling confusion across temporal execution windows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub start_time_nanos: u64,
    pub executable_path: String,
    pub executable_hash: Option<String>,
    pub generation_id: u64,
    pub command_line: Vec<String>,
    pub user: Option<String>,
}

impl ProcessIdentity {
    pub fn new(
        pid: u32,
        ppid: Option<u32>,
        start_time_nanos: u64,
        executable_path: impl Into<String>,
        generation_id: u64,
    ) -> Self {
        Self {
            pid,
            ppid,
            start_time_nanos,
            executable_path: executable_path.into(),
            executable_hash: None,
            generation_id,
            command_line: Vec::new(),
            user: None,
        }
    }

    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.executable_hash = Some(hash.into());
        self
    }

    pub fn with_command_line(mut self, args: Vec<String>) -> Self {
        self.command_line = args;
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Derives a deterministic canonical key for process identity matching across runs.
    pub fn canonical_name(&self) -> &str {
        if self.executable_path.is_empty() {
            return "unknown";
        }
        let s = self.executable_path.as_str();
        let last_sep = s.rfind(|c| c == '/' || c == '\\');
        match last_sep {
            Some(idx) => {
                let name = &s[idx + 1..];
                if name.is_empty() {
                    s
                } else {
                    name
                }
            }
            None => s,
        }
    }
}

impl fmt::Display for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [pid:{}, gen:{}]",
            self.canonical_name(),
            self.pid,
            self.generation_id
        )
    }
}

/// Identifies an OS execution thread within a process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreadIdentity {
    pub tid: u64,
    pub thread_name: Option<String>,
}

impl ThreadIdentity {
    pub fn new(tid: u64) -> Self {
        Self {
            tid,
            thread_name: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.thread_name = Some(name.into());
        self
    }
}
