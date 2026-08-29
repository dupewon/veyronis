use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

// ==========================================
// Process Events
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStartData {
    pub executable_path: String,
    pub command_line: Vec<String>,
    pub working_directory: Option<String>,
    pub parent_pid: Option<u32>,
    pub environment_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExitData {
    pub exit_code: i32,
    pub termination_signal: Option<i32>,
    pub cpu_user_time_ms: u64,
    pub cpu_system_time_ms: u64,
    pub max_resident_set_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSpawnData {
    pub child_pid: u32,
    pub child_executable_path: String,
    pub command_line: Vec<String>,
}

// ==========================================
// File Events
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOpenData {
    pub path: String,
    pub normalized_path: String,
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReadData {
    pub path: String,
    pub bytes_read: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteData {
    pub path: String,
    pub bytes_written: u64,
    pub offset: u64,
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDeleteData {
    pub path: String,
    pub normalized_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRenameData {
    pub old_path: String,
    pub new_path: String,
}

// ==========================================
// Network & DNS Events
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryData {
    pub query_name: String,
    pub record_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResponseData {
    pub query_name: String,
    pub record_type: String,
    pub addresses: Vec<String>,
    pub rcode: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnectData {
    pub protocol: NetworkProtocol,
    pub local_address: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub remote_hostname: Option<String>,
    pub is_external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAcceptData {
    pub protocol: NetworkProtocol,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCloseData {
    pub protocol: NetworkProtocol,
    pub local_address: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_address: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketCreateData {
    pub domain: String,
    pub socket_type: String,
    pub protocol: String,
}

// ==========================================
// Cryptography Telemetry
// ==========================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CryptoCategory {
    Hash,
    Sign,
    Verify,
    Rng,
    Tls,
    Encrypt,
    Decrypt,
    Kdf,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoOperationData {
    pub category: CryptoCategory,
    pub algorithm: String,
    pub provider: String,
    pub key_size_bits: Option<u32>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsObservedData {
    pub version: String,
    pub cipher_suite: Option<String>,
    pub server_name: Option<String>,
    pub peer_certificate_sha256: Option<String>,
}

// ==========================================
// Memory & IPC Events
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryMapData {
    pub address: u64,
    pub size_bytes: u64,
    pub permissions: String,
    pub backed_file_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProtectData {
    pub address: u64,
    pub size_bytes: u64,
    pub old_permissions: Option<String>,
    pub new_permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcConnectData {
    pub ipc_type: String,
    pub target_endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcSendData {
    pub ipc_type: String,
    pub target_endpoint: String,
    pub message_bytes: u64,
}

// ==========================================
// System & User Metadata
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSessionData {
    pub username: String,
    pub session_id: String,
    pub is_elevated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemMetadataData {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub cpu_count: usize,
    pub custom_properties: BTreeMap<String, String>,
}

// ==========================================
// Master EventData Enum
// ==========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "category", content = "payload")]
pub enum EventData {
    ProcessStart(ProcessStartData),
    ProcessExit(ProcessExitData),
    ProcessSpawn(ProcessSpawnData),
    FileOpen(FileOpenData),
    FileRead(FileReadData),
    FileWrite(FileWriteData),
    FileDelete(FileDeleteData),
    FileRename(FileRenameData),
    DnsQuery(DnsQueryData),
    DnsResponse(DnsResponseData),
    NetworkConnect(NetworkConnectData),
    NetworkAccept(NetworkAcceptData),
    NetworkClose(NetworkCloseData),
    SocketCreate(SocketCreateData),
    CryptoOperation(CryptoOperationData),
    TlsObserved(TlsObservedData),
    MemoryMap(MemoryMapData),
    MemoryProtect(MemoryProtectData),
    IpcConnect(IpcConnectData),
    IpcSend(IpcSendData),
    UserSession(UserSessionData),
    SystemMetadata(SystemMetadataData),
}
