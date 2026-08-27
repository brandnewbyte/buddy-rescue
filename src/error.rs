use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum RescueError {
    #[error("{0}")]
    InvalidDatabase(String),

    #[error("vault {vault_id} uses unsupported format version {version}")]
    UnsupportedVaultVersion { vault_id: String, version: i64 },

    #[error("database schema migration {0} is not supported; this build supports migration 1")]
    UnsupportedSchemaVersion(i64),

    #[error("this database contains multiple vaults; choose one with --vault <id>\n{0}")]
    VaultSelectionRequired(String),

    #[error("vault not found: {0}")]
    VaultNotFound(String),

    #[error("the master password is incorrect or the vault verifier is damaged")]
    InvalidPassword,

    #[error("output already exists: {0}")]
    OutputExists(PathBuf),

    #[error("refusing to replace {0}: it is not a buddy-rescue export")]
    UnsafeReplacement(PathBuf),

    #[error("{action}: {source}")]
    Io {
        action: String,
        #[source]
        source: std::io::Error,
    },

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
}

impl RescueError {
    pub fn io(action: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            action: action.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, RescueError>;
