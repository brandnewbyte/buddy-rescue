use buddy_crypto_core::KdfParams;
use serde::Serialize;
use serde_json::{Map, Value};
use std::path::PathBuf;

pub const SUPPORTED_SCHEMA_VERSION: i64 = 1;
pub const SUPPORTED_VAULT_VERSION: i64 = 1;
pub const EXPORT_FORMAT: &str = "buddy-rescue-export-v1";

#[derive(Debug, Clone)]
pub(crate) struct VaultRecord {
    pub id: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub name: String,
    pub color: Option<String>,
    pub hint_present: bool,
    pub biometrics_enabled: bool,
    pub kdf_algo: String,
    pub kdf_mem_cost: i64,
    pub kdf_time_cost: i64,
    pub kdf_parallelism: i64,
    pub kdf_version: i64,
    pub password_changed_at: i64,
    pub version: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl VaultRecord {
    pub fn kdf_params(&self) -> std::result::Result<KdfParams, String> {
        if self.kdf_mem_cost > 1_048_576 {
            return Err("kdf_mem_cost exceeds the 1 GiB safety limit".to_string());
        }
        if self.kdf_time_cost > 20 {
            return Err("kdf_time_cost exceeds the safety limit of 20 iterations".to_string());
        }
        if self.kdf_parallelism > 64 {
            return Err("kdf_parallelism exceeds the safety limit of 64 lanes".to_string());
        }

        Ok(KdfParams {
            algo: self.kdf_algo.clone(),
            mem_cost: checked_u32("kdf_mem_cost", self.kdf_mem_cost)?,
            time_cost: checked_u32("kdf_time_cost", self.kdf_time_cost)?,
            parallelism: checked_u32("kdf_parallelism", self.kdf_parallelism)?,
            version: checked_u32("kdf_version", self.kdf_version)?,
        })
    }
}

fn checked_u32(name: &str, value: i64) -> std::result::Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{name} is outside the supported range: {value}"))
}

pub(crate) fn exact_bytes<const N: usize>(
    field: &str,
    value: &[u8],
) -> std::result::Result<[u8; N], String> {
    value
        .try_into()
        .map_err(|_| format!("{field} is {} bytes; expected {N}", value.len()))
}

#[derive(Debug, Clone)]
pub(crate) struct EntryRecord {
    pub id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub used_at: Option<i64>,
    pub used_count: i64,
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub(crate) struct BlobRecord {
    pub id: String,
    pub entry_id: Option<String>,
    pub nonce: Vec<u8>,
    pub envelope_nonce: Vec<u8>,
    pub envelope_ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub format: &'static str,
    pub integrity: Integrity,
    pub schema_version: Option<i64>,
    pub compatible: bool,
    pub attachments_directory: PathBuf,
    pub vaults: Vec<VaultInspection>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    Ok,
    Failed { messages: Vec<String> },
}

#[derive(Debug, Serialize)]
pub struct VaultInspection {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    pub hint_present: bool,
    pub biometrics_enabled: bool,
    pub version: i64,
    pub compatible: bool,
    pub kdf: KdfInspection,
    pub live_entries: u64,
    pub trashed_entries: u64,
    pub attachments: u64,
    pub attachment_files_present: u64,
    pub attachment_files_missing: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub password_changed_at: i64,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct KdfInspection {
    pub algorithm: String,
    pub memory_kib: i64,
    pub iterations: i64,
    pub parallelism: i64,
    pub version: i64,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ExportKind {
    Json,
    Csv,
}

impl ExportKind {
    pub fn filename(self) -> &'static str {
        match self {
            Self::Json => "entries.json",
            Self::Csv => "entries.csv",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }
}

pub struct ExportRequest {
    pub database: PathBuf,
    pub attachments: Option<PathBuf>,
    pub vault_id: Option<String>,
    pub password: zeroize::Zeroizing<String>,
    pub kind: ExportKind,
    pub output: PathBuf,
    pub force: bool,
}

#[derive(Debug)]
pub struct ExportSummary {
    pub output: PathBuf,
    pub entries: usize,
    pub attachments: usize,
    pub issues: usize,
    pub warning: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExportEntry {
    pub id: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_at: Option<i64>,
    pub used_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    #[serde(flatten)]
    pub payload: Map<String, Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EntriesDocument<'a> {
    pub format: &'static str,
    pub vault_id: &'a str,
    pub entries: &'a [ExportEntry],
}

#[derive(Debug, Serialize)]
pub(crate) struct Manifest {
    pub format: &'static str,
    pub tool: ToolIdentity,
    pub exported_at: i64,
    pub vault: ExportVault,
    pub entries: ExportedFile,
    pub attachments: Vec<AttachmentManifest>,
    pub issues: Vec<ExportIssue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolIdentity {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExportVault {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    pub version: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub password_changed_at: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExportedFile {
    pub path: String,
    pub format: &'static str,
    pub recovered: usize,
    pub skipped: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct AttachmentManifest {
    pub id: String,
    pub entry_id: Option<String>,
    pub filename: String,
    pub mime_type: Option<String>,
    pub declared_size: Option<u64>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    pub path: Option<String>,
    pub status: AttachmentStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttachmentStatus {
    Recovered,
    MissingMetadata,
    MissingCiphertext,
    InvalidMetadata,
    AuthenticationFailed,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExportIssue {
    pub record_type: &'static str,
    pub id: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub(crate) struct FileReference {
    pub filename: String,
    pub mime_type: Option<String>,
    pub size: Option<u64>,
}
