use crate::error::{RescueError, Result};
use crate::model::{
    BlobRecord, EntryRecord, Inspection, Integrity, KdfInspection, SUPPORTED_SCHEMA_VERSION,
    SUPPORTED_VAULT_VERSION, VaultInspection, VaultRecord,
};
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const REQUIRED_SCHEMA: &[(&str, &[&str])] = &[
    ("migrations", &["version", "created_at"]),
    (
        "vault",
        &[
            "id",
            "salt",
            "nonce",
            "ciphertext",
            "name",
            "color",
            "hint",
            "biometrics_enabled",
            "kdf_algo",
            "kdf_mem_cost",
            "kdf_time_cost",
            "kdf_parallelism",
            "kdf_version",
            "password_changed_at",
            "version",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "entry",
        &[
            "id",
            "vault_id",
            "nonce",
            "ciphertext",
            "created_at",
            "updated_at",
            "used_at",
            "used_count",
            "deleted_at",
        ],
    ),
    (
        "entry_blob",
        &[
            "id",
            "vault_id",
            "entry_id",
            "nonce",
            "envelope_nonce",
            "envelope_ciphertext",
            "created_at",
            "updated_at",
        ],
    ),
];

pub(crate) struct Database {
    conn: Connection,
    pub attachments: PathBuf,
}

impl Database {
    pub fn open(path: &Path, attachments: Option<&Path>) -> Result<Self> {
        if !path.is_file() {
            return Err(RescueError::InvalidDatabase(format!(
                "database file does not exist: {}",
                path.display()
            )));
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.pragma_update(None, "query_only", true)?;

        let default_attachments = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("attachments");

        Ok(Self {
            conn,
            attachments: attachments.unwrap_or(&default_attachments).to_path_buf(),
        })
    }

    pub fn schema_issues(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        for (table, required_columns) in REQUIRED_SCHEMA {
            let columns = self.table_columns(table)?;
            if columns.is_empty() {
                issues.push(format!("required table is missing: {table}"));
                continue;
            }

            for column in *required_columns {
                if !columns.contains(*column) {
                    issues.push(format!("required column is missing: {table}.{column}"));
                }
            }
        }

        Ok(issues)
    }

    pub fn schema_version(&self) -> Result<Option<i64>> {
        if self.table_columns("migrations")?.is_empty() {
            return Ok(None);
        }

        self.conn
            .query_row("SELECT MAX(version) FROM migrations", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn integrity(&self) -> Result<Integrity> {
        let mut statement = self.conn.prepare("PRAGMA integrity_check")?;
        let messages = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        if messages.as_slice() == ["ok"] {
            Ok(Integrity::Ok)
        } else {
            Ok(Integrity::Failed { messages })
        }
    }

    pub fn vaults(&self) -> Result<Vec<VaultRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, salt, nonce, ciphertext, name, color, hint IS NOT NULL,
                    biometrics_enabled, kdf_algo, kdf_mem_cost, kdf_time_cost,
                    kdf_parallelism, kdf_version, password_changed_at, version,
                    created_at, updated_at
             FROM vault
             ORDER BY created_at, id",
        )?;

        statement
            .query_map([], |row| {
                Ok(VaultRecord {
                    id: row.get(0)?,
                    salt: row.get(1)?,
                    nonce: row.get(2)?,
                    ciphertext: row.get(3)?,
                    name: row.get(4)?,
                    color: row.get(5)?,
                    hint_present: row.get(6)?,
                    biometrics_enabled: row.get::<_, i64>(7)? != 0,
                    kdf_algo: row.get(8)?,
                    kdf_mem_cost: row.get(9)?,
                    kdf_time_cost: row.get(10)?,
                    kdf_parallelism: row.get(11)?,
                    kdf_version: row.get(12)?,
                    password_changed_at: row.get(13)?,
                    version: row.get(14)?,
                    created_at: row.get(15)?,
                    updated_at: row.get(16)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn entries(&self, vault_id: &str) -> Result<Vec<EntryRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, nonce, ciphertext, created_at, updated_at, used_at,
                    used_count, deleted_at
             FROM entry
             WHERE vault_id = ?
             ORDER BY created_at, id",
        )?;

        statement
            .query_map([vault_id], |row| {
                Ok(EntryRecord {
                    id: row.get(0)?,
                    nonce: row.get(1)?,
                    ciphertext: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                    used_at: row.get(5)?,
                    used_count: row.get(6)?,
                    deleted_at: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn blobs(&self, vault_id: &str) -> Result<Vec<BlobRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, entry_id, nonce, envelope_nonce, envelope_ciphertext,
                    created_at, updated_at
             FROM entry_blob
             WHERE vault_id = ?
             ORDER BY id",
        )?;

        statement
            .query_map([vault_id], |row| {
                Ok(BlobRecord {
                    id: row.get(0)?,
                    entry_id: row.get(1)?,
                    nonce: row.get(2)?,
                    envelope_nonce: row.get(3)?,
                    envelope_ciphertext: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn require_exportable_schema(&self) -> Result<()> {
        let issues = self.schema_issues()?;
        if !issues.is_empty() {
            return Err(RescueError::InvalidDatabase(issues.join("; ")));
        }

        let version = self.schema_version()?.unwrap_or(0);
        if version != SUPPORTED_SCHEMA_VERSION {
            return Err(RescueError::UnsupportedSchemaVersion(version));
        }

        Ok(())
    }

    fn table_columns(&self, table: &str) -> Result<BTreeSet<String>> {
        let sql = format!("PRAGMA table_info({table})");
        let mut statement = self.conn.prepare(&sql)?;
        statement
            .query_map([], |row| row.get(1))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()
            .map_err(Into::into)
    }

    fn counts(&self, vault_id: &str) -> Result<(u64, u64, u64)> {
        let (live, trashed): (i64, i64) = self.conn.query_row(
            "SELECT
                COALESCE(SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END), 0)
             FROM entry WHERE vault_id = ?",
            [vault_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let blobs: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM entry_blob WHERE vault_id = ?",
            [vault_id],
            |row| row.get(0),
        )?;

        Ok((
            live.max(0) as u64,
            trashed.max(0) as u64,
            blobs.max(0) as u64,
        ))
    }

    fn malformed_record_counts(&self, vault_id: &str) -> Result<(i64, i64)> {
        let entries = self.conn.query_row(
            "SELECT COUNT(*) FROM entry
             WHERE vault_id = ? AND (length(nonce) != 24 OR length(ciphertext) < 16)",
            [vault_id],
            |row| row.get(0),
        )?;
        let blobs = self.conn.query_row(
            "SELECT COUNT(*) FROM entry_blob
             WHERE vault_id = ? AND (
                length(nonce) != 24 OR length(envelope_nonce) != 24 OR
                length(envelope_ciphertext) != 48
             )",
            [vault_id],
            |row| row.get(0),
        )?;

        Ok((entries, blobs))
    }

    fn attachment_file_counts(&self, vault_id: &str) -> Result<(u64, u64, Vec<String>)> {
        let mut present = 0;
        let mut missing = 0;
        let mut issues = Vec::new();
        let mut statement = self
            .conn
            .prepare("SELECT id FROM entry_blob WHERE vault_id = ? ORDER BY id")?;
        let ids = statement
            .query_map([vault_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        if !safe_component(vault_id) {
            issues.push("vault id cannot be represented safely as an attachment path".to_string());
            return Ok((0, ids.len() as u64, issues));
        }

        for id in ids {
            if !safe_component(&id) {
                missing += 1;
                issues.push(format!("attachment {id} has an unsafe path component"));
            } else if self.attachments.join(vault_id).join(&id).is_file() {
                present += 1;
            } else {
                missing += 1;
            }
        }

        Ok((present, missing, issues))
    }
}

pub fn inspect(database: &Path, attachments: Option<&Path>) -> Result<Inspection> {
    let database = Database::open(database, attachments)?;
    let integrity = database.integrity()?;
    let schema_version = database.schema_version()?;
    let mut issues = database.schema_issues()?;
    let schema_ready = issues.is_empty();

    if schema_version != Some(SUPPORTED_SCHEMA_VERSION) {
        issues.push(format!(
            "schema migration {} is not supported by this build",
            schema_version
                .map(|version| version.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ));
    }

    let mut vaults = Vec::new();
    if schema_ready {
        for vault in database.vaults()? {
            vaults.push(database.inspect_vault(vault)?);
        }
    }

    let integrity_ok = matches!(integrity, Integrity::Ok);
    let compatible =
        integrity_ok && issues.is_empty() && vaults.iter().all(|vault| vault.compatible);

    Ok(Inspection {
        format: "buddy-vault-v1",
        integrity,
        schema_version,
        compatible,
        attachments_directory: database.attachments,
        vaults,
        issues,
    })
}

impl Database {
    fn inspect_vault(&self, vault: VaultRecord) -> Result<VaultInspection> {
        let mut issues = Vec::new();

        if vault.version != SUPPORTED_VAULT_VERSION {
            issues.push(format!("unsupported vault version: {}", vault.version));
        }
        if vault.salt.len() != 16 {
            issues.push(format!("salt is {} bytes; expected 16", vault.salt.len()));
        }
        if vault.nonce.len() != 24 {
            issues.push(format!(
                "verifier nonce is {} bytes; expected 24",
                vault.nonce.len()
            ));
        }
        if vault.ciphertext.len() != 48 {
            issues.push(format!(
                "verifier ciphertext is {} bytes; expected 48",
                vault.ciphertext.len()
            ));
        }
        if let Err(error) = vault
            .kdf_params()
            .and_then(|params| params.argon2().map(|_| ()))
        {
            issues.push(error);
        }

        let (live_entries, trashed_entries, attachments) = self.counts(&vault.id)?;
        let (invalid_entries, invalid_blobs) = self.malformed_record_counts(&vault.id)?;
        if invalid_entries != 0 {
            issues.push(format!(
                "{invalid_entries} entry record(s) have invalid lengths"
            ));
        }
        if invalid_blobs != 0 {
            issues.push(format!(
                "{invalid_blobs} attachment record(s) have invalid lengths"
            ));
        }

        let (attachment_files_present, attachment_files_missing, path_issues) =
            self.attachment_file_counts(&vault.id)?;
        issues.extend(path_issues);

        Ok(VaultInspection {
            id: vault.id,
            name: vault.name,
            color: vault.color,
            hint_present: vault.hint_present,
            biometrics_enabled: vault.biometrics_enabled,
            version: vault.version,
            compatible: issues.is_empty(),
            kdf: KdfInspection {
                algorithm: vault.kdf_algo,
                memory_kib: vault.kdf_mem_cost,
                iterations: vault.kdf_time_cost,
                parallelism: vault.kdf_parallelism,
                version: vault.kdf_version,
            },
            live_entries,
            trashed_entries,
            attachments,
            attachment_files_present,
            attachment_files_missing,
            created_at: vault.created_at,
            updated_at: vault.updated_at,
            password_changed_at: vault.password_changed_at,
            issues,
        })
    }
}

pub(crate) fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|character| character.is_control() || "\\/:*?\"<>|".contains(character))
}

pub(crate) fn choose_vault(
    vaults: Vec<VaultRecord>,
    requested: Option<&str>,
) -> Result<VaultRecord> {
    if let Some(id) = requested {
        return vaults
            .into_iter()
            .find(|vault| vault.id == id)
            .ok_or_else(|| RescueError::VaultNotFound(id.to_string()));
    }

    match vaults.len() {
        0 => Err(RescueError::InvalidDatabase(
            "database contains no vaults".to_string(),
        )),
        1 => Ok(vaults.into_iter().next().expect("length checked")),
        _ => {
            let choices = vaults
                .iter()
                .map(|vault| format!("  {}  {}", vault.id, vault.name))
                .collect::<Vec<_>>()
                .join("\n");
            Err(RescueError::VaultSelectionRequired(choices))
        }
    }
}
