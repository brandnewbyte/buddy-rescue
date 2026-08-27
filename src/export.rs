use crate::database::{Database, choose_vault, safe_component};
use crate::error::{RescueError, Result};
use crate::model::{
    AttachmentManifest, AttachmentStatus, BlobRecord, EXPORT_FORMAT, EntriesDocument, ExportEntry,
    ExportIssue, ExportKind, ExportRequest, ExportSummary, ExportVault, ExportedFile,
    FileReference, Manifest, SUPPORTED_VAULT_VERSION, ToolIdentity, exact_bytes,
};
use buddy_crypto_core::{
    Crypto, ENTRY_BLOB_CTX, ENTRY_CTX, derive_subkey, entry_aad, entry_blob_envelope_aad,
    verify_master_password,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use zeroize::Zeroizing;

const CSV_WARNING: &str = "CSV is a compatibility format and omits custom fields, SSH fields, field history, trash state, and icons; use JSON for full-fidelity recovery";
const RESERVED_PAYLOAD_KEYS: &[&str] = &[
    "id",
    "created_at",
    "updated_at",
    "used_at",
    "used_count",
    "deleted_at",
];

pub fn export(request: ExportRequest) -> Result<ExportSummary> {
    let database = Database::open(&request.database, request.attachments.as_deref())?;
    database.require_exportable_schema()?;

    let vault = choose_vault(database.vaults()?, request.vault_id.as_deref())?;
    if vault.version != SUPPORTED_VAULT_VERSION {
        return Err(RescueError::UnsupportedVaultVersion {
            vault_id: vault.id,
            version: vault.version,
        });
    }

    let salt =
        exact_bytes::<16>("vault salt", &vault.salt).map_err(RescueError::InvalidDatabase)?;
    let verifier_nonce = exact_bytes::<24>("vault verifier nonce", &vault.nonce)
        .map_err(RescueError::InvalidDatabase)?;
    if vault.ciphertext.len() != 48 {
        return Err(RescueError::InvalidDatabase(format!(
            "vault verifier ciphertext is {} bytes; expected 48",
            vault.ciphertext.len()
        )));
    }
    let kdf = vault.kdf_params().map_err(RescueError::InvalidDatabase)?;
    kdf.argon2().map_err(RescueError::InvalidDatabase)?;
    let master_key = verify_master_password(
        &salt,
        &verifier_nonce,
        &vault.ciphertext,
        request.password.as_bytes(),
        &kdf,
    )
    .map_err(|_| RescueError::InvalidPassword)?;
    let entry_key = Zeroizing::new(derive_subkey(&master_key, ENTRY_CTX));
    let blob_key = Zeroizing::new(derive_subkey(&master_key, ENTRY_BLOB_CTX));

    let source_entry_count = database.entries(&vault.id)?.len();
    let decrypted = decrypt_entries(&database, &vault.id, &entry_key)?;
    let entries = decrypted.entries;
    let references = decrypted.references;
    let mut issues = decrypted.issues;

    let parent = output_parent(&request.output);
    fs::create_dir_all(parent)
        .map_err(|error| RescueError::io(format!("create {}", parent.display()), error))?;
    let staging = tempfile::Builder::new()
        .prefix(".buddy-rescue-")
        .tempdir_in(parent)
        .map_err(|error| RescueError::io("create temporary export directory", error))?;

    write_entries(staging.path(), request.kind, &vault.id, &entries)?;
    let (attachments, recovered_attachments, attachment_issues) =
        recover_attachments(&database, staging.path(), &vault.id, &blob_key, references)?;
    issues.extend(attachment_issues);

    let warning = matches!(request.kind, ExportKind::Csv).then_some(CSV_WARNING);
    let manifest = Manifest {
        format: EXPORT_FORMAT,
        tool: ToolIdentity {
            name: "buddy-rescue",
            version: env!("CARGO_PKG_VERSION"),
        },
        exported_at: unix_timestamp(),
        vault: ExportVault {
            id: vault.id,
            name: vault.name,
            color: vault.color,
            version: vault.version,
            created_at: vault.created_at,
            updated_at: vault.updated_at,
            password_changed_at: vault.password_changed_at,
        },
        entries: ExportedFile {
            path: request.kind.filename().to_string(),
            format: request.kind.label(),
            recovered: entries.len(),
            skipped: source_entry_count.saturating_sub(entries.len()),
        },
        attachments,
        issues,
        warnings: warning.into_iter().map(str::to_string).collect(),
    };
    write_json(staging.path().join("manifest.json"), &manifest)?;

    finalize_output(staging, &request.output, request.force)?;

    Ok(ExportSummary {
        output: request.output,
        entries: entries.len(),
        attachments: recovered_attachments,
        issues: manifest.issues.len(),
        warning,
    })
}

struct DecryptedEntries {
    entries: Vec<ExportEntry>,
    references: BTreeMap<String, FileReference>,
    issues: Vec<ExportIssue>,
}

fn decrypt_entries(
    database: &Database,
    vault_id: &str,
    key: &[u8; 32],
) -> Result<DecryptedEntries> {
    let mut entries = Vec::new();
    let mut references = BTreeMap::new();
    let mut issues = Vec::new();

    for row in database.entries(vault_id)? {
        let nonce = match exact_bytes::<24>("entry nonce", &row.nonce) {
            Ok(nonce) => nonce,
            Err(message) => {
                issues.push(entry_issue(&row.id, message));
                continue;
            }
        };
        if row.ciphertext.len() < 16 {
            issues.push(entry_issue(
                &row.id,
                format!(
                    "ciphertext is {} bytes; expected at least 16",
                    row.ciphertext.len()
                ),
            ));
            continue;
        }

        let aad = entry_aad(vault_id, &row.id);
        let plaintext = match Crypto::decrypt_bytes_with_aad(*key, nonce, &row.ciphertext, &aad) {
            Ok(plaintext) => Zeroizing::new(plaintext),
            Err(_) => {
                issues.push(entry_issue(
                    &row.id,
                    "authenticated decryption failed".to_string(),
                ));
                continue;
            }
        };
        let value: Value = match serde_json::from_slice(plaintext.as_slice()) {
            Ok(value) => value,
            Err(error) => {
                issues.push(entry_issue(
                    &row.id,
                    format!("decrypted payload is invalid JSON: {error}"),
                ));
                continue;
            }
        };
        let Value::Object(payload) = value else {
            issues.push(entry_issue(
                &row.id,
                "decrypted payload is not a JSON object".to_string(),
            ));
            continue;
        };
        if let Some(key) = RESERVED_PAYLOAD_KEYS
            .iter()
            .find(|key| payload.contains_key(**key))
        {
            issues.push(entry_issue(
                &row.id,
                format!("decrypted payload contains reserved property {key}"),
            ));
            continue;
        }

        collect_file_references(&payload, &mut references);
        entries.push(ExportEntry {
            id: row.id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            used_at: row.used_at,
            used_count: row.used_count,
            deleted_at: row.deleted_at,
            payload,
        });
    }

    Ok(DecryptedEntries {
        entries,
        references,
        issues,
    })
}

fn recover_attachments(
    database: &Database,
    output: &Path,
    vault_id: &str,
    key: &[u8; 32],
    mut references: BTreeMap<String, FileReference>,
) -> Result<(Vec<AttachmentManifest>, usize, Vec<ExportIssue>)> {
    let mut manifest = Vec::new();
    let mut recovered = 0;
    let mut issues = Vec::new();
    let blobs = database.blobs(vault_id)?;
    let blob_ids = blobs
        .iter()
        .map(|blob| blob.id.clone())
        .collect::<BTreeSet<_>>();

    for blob in blobs {
        let reference = references.remove(&blob.id);
        let AttachmentOutcome {
            manifest: item,
            issue,
        } = recover_attachment(database, output, vault_id, key, blob, reference);
        if matches!(item.status, AttachmentStatus::Recovered) {
            recovered += 1;
        }
        if let Some(issue) = issue {
            issues.push(issue);
        }
        manifest.push(item);
    }

    for (id, reference) in references {
        if blob_ids.contains(&id) {
            continue;
        }
        issues.push(attachment_issue(
            &id,
            "attachment is referenced by an entry but has no database row".to_string(),
        ));
        manifest.push(AttachmentManifest {
            id,
            entry_id: None,
            filename: reference.filename,
            mime_type: reference.mime_type,
            declared_size: reference.size,
            created_at: None,
            updated_at: None,
            path: None,
            status: AttachmentStatus::MissingMetadata,
        });
    }

    Ok((manifest, recovered, issues))
}

struct AttachmentOutcome {
    manifest: AttachmentManifest,
    issue: Option<ExportIssue>,
}

fn recover_attachment(
    database: &Database,
    output: &Path,
    vault_id: &str,
    key: &[u8; 32],
    blob: BlobRecord,
    reference: Option<FileReference>,
) -> AttachmentOutcome {
    let filename = reference
        .as_ref()
        .map(|reference| reference.filename.clone())
        .unwrap_or_else(|| format!("{}.bin", blob.id));
    let mime_type = reference
        .as_ref()
        .and_then(|reference| reference.mime_type.clone());
    let declared_size = reference.as_ref().and_then(|reference| reference.size);
    let base_manifest = |status, path| AttachmentManifest {
        id: blob.id.clone(),
        entry_id: blob.entry_id.clone(),
        filename: filename.clone(),
        mime_type: mime_type.clone(),
        declared_size,
        created_at: Some(blob.created_at),
        updated_at: Some(blob.updated_at),
        path,
        status,
    };

    if !safe_component(vault_id) || !safe_component(&blob.id) {
        let message = "record id cannot be represented safely as an attachment path".to_string();
        return AttachmentOutcome {
            manifest: base_manifest(AttachmentStatus::InvalidMetadata, None),
            issue: Some(attachment_issue(&blob.id, message)),
        };
    }

    let nonce = match exact_bytes::<24>("attachment nonce", &blob.nonce) {
        Ok(value) => value,
        Err(message) => {
            return AttachmentOutcome {
                manifest: base_manifest(AttachmentStatus::InvalidMetadata, None),
                issue: Some(attachment_issue(&blob.id, message)),
            };
        }
    };
    let envelope_nonce = match exact_bytes::<24>("attachment envelope nonce", &blob.envelope_nonce)
    {
        Ok(value) => value,
        Err(message) => {
            return AttachmentOutcome {
                manifest: base_manifest(AttachmentStatus::InvalidMetadata, None),
                issue: Some(attachment_issue(&blob.id, message)),
            };
        }
    };
    if blob.envelope_ciphertext.len() != 48 {
        let message = format!(
            "attachment envelope ciphertext is {} bytes; expected 48",
            blob.envelope_ciphertext.len()
        );
        return AttachmentOutcome {
            manifest: base_manifest(AttachmentStatus::InvalidMetadata, None),
            issue: Some(attachment_issue(&blob.id, message)),
        };
    }

    let envelope_aad = entry_blob_envelope_aad(vault_id, &blob.id);
    let data_key = match Crypto::decrypt_bytes_with_aad(
        *key,
        envelope_nonce,
        &blob.envelope_ciphertext,
        &envelope_aad,
    ) {
        Ok(value) => value,
        Err(_) => {
            return AttachmentOutcome {
                manifest: base_manifest(AttachmentStatus::AuthenticationFailed, None),
                issue: Some(attachment_issue(
                    &blob.id,
                    "attachment key authentication failed".to_string(),
                )),
            };
        }
    };
    let data_key = match exact_bytes::<32>("decrypted attachment key", &data_key) {
        Ok(value) => Zeroizing::new(value),
        Err(message) => {
            return AttachmentOutcome {
                manifest: base_manifest(AttachmentStatus::InvalidMetadata, None),
                issue: Some(attachment_issue(&blob.id, message)),
            };
        }
    };

    let source = database.attachments.join(vault_id).join(&blob.id);
    let ciphertext = match fs::read(&source) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return AttachmentOutcome {
                manifest: base_manifest(AttachmentStatus::MissingCiphertext, None),
                issue: Some(attachment_issue(
                    &blob.id,
                    format!("ciphertext file is missing: {}", source.display()),
                )),
            };
        }
        Err(error) => {
            return AttachmentOutcome {
                manifest: base_manifest(AttachmentStatus::MissingCiphertext, None),
                issue: Some(attachment_issue(
                    &blob.id,
                    format!("could not read ciphertext file: {error}"),
                )),
            };
        }
    };
    let plaintext = match Crypto::decrypt_bytes(*data_key, nonce, &ciphertext) {
        Ok(value) => Zeroizing::new(value),
        Err(_) => {
            return AttachmentOutcome {
                manifest: base_manifest(AttachmentStatus::AuthenticationFailed, None),
                issue: Some(attachment_issue(
                    &blob.id,
                    "attachment content authentication failed".to_string(),
                )),
            };
        }
    };

    let safe_filename = sanitize_filename(&filename);
    let relative = format!("attachments/{}/{}", blob.id, safe_filename);
    let destination_directory = output.join("attachments").join(&blob.id);
    let destination = destination_directory.join(&safe_filename);
    let result = fs::create_dir_all(&destination_directory)
        .and_then(|_| fs::write(&destination, plaintext.as_slice()))
        .and_then(|_| make_private_path(&destination));
    if let Err(error) = result {
        return AttachmentOutcome {
            manifest: base_manifest(AttachmentStatus::InvalidMetadata, None),
            issue: Some(attachment_issue(
                &blob.id,
                format!("could not write recovered attachment: {error}"),
            )),
        };
    }

    let size_issue = declared_size
        .filter(|size| *size != plaintext.len() as u64)
        .map(|size| {
            attachment_issue(
                &blob.id,
                format!(
                    "declared size is {size} bytes but recovered content is {} bytes",
                    plaintext.len()
                ),
            )
        });

    AttachmentOutcome {
        manifest: base_manifest(AttachmentStatus::Recovered, Some(relative)),
        issue: size_issue,
    }
}

fn write_entries(
    output: &Path,
    kind: ExportKind,
    vault_id: &str,
    entries: &[ExportEntry],
) -> Result<()> {
    match kind {
        ExportKind::Json => {
            let document = EntriesDocument {
                format: "buddy-rescue-entries-v1",
                vault_id,
                entries,
            };
            write_json(output.join(kind.filename()), &document)
        }
        ExportKind::Csv => write_csv(output.join(kind.filename()), entries),
    }
}

fn write_json(path: PathBuf, value: &impl serde::Serialize) -> Result<()> {
    let file = File::create(&path)
        .map_err(|error| RescueError::io(format!("create {}", path.display()), error))?;
    make_private_file(&file)
        .map_err(|error| RescueError::io(format!("protect {}", path.display()), error))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer
        .write_all(b"\n")
        .map_err(|error| RescueError::io(format!("write {}", path.display()), error))?;
    writer
        .flush()
        .map_err(|error| RescueError::io(format!("flush {}", path.display()), error))
}

fn write_csv(path: PathBuf, entries: &[ExportEntry]) -> Result<()> {
    let file = File::create(&path)
        .map_err(|error| RescueError::io(format!("create {}", path.display()), error))?;
    make_private_file(&file)
        .map_err(|error| RescueError::io(format!("protect {}", path.display()), error))?;
    let mut writer = csv::Writer::from_writer(file);
    writer.write_record([
        "Title",
        "Tags",
        "Notes",
        "Username",
        "Password",
        "URL",
        "Two-Factor Secret",
        "Cardholder Name",
        "Card Number",
        "Card Expiration",
        "Card CVV",
    ])?;

    for entry in entries {
        let mut row: [String; 11] = Default::default();
        for field in fields(&entry.payload) {
            let Some(role) = field.get("role").and_then(Value::as_str) else {
                continue;
            };
            let Some(value) = field.get("value") else {
                continue;
            };
            match role {
                "title" => row[0] = string_value(value).unwrap_or_default(),
                "tags" => row[1] = string_vec_value(value).unwrap_or_default(),
                "note" => row[2] = string_value(value).unwrap_or_default(),
                "username" => row[3] = string_value(value).unwrap_or_default(),
                "password" => row[4] = string_value(value).unwrap_or_default(),
                "url" => row[5] = string_value(value).unwrap_or_default(),
                "totp" => row[6] = totp_value(value).unwrap_or_default(),
                "card_name" => row[7] = string_value(value).unwrap_or_default(),
                "card_number" => row[8] = string_value(value).unwrap_or_default(),
                "card_exp" => row[9] = string_value(value).unwrap_or_default(),
                "card_cvv" => row[10] = string_value(value).unwrap_or_default(),
                _ => {}
            }
        }
        writer.write_record(row)?;
    }

    writer
        .flush()
        .map_err(|error| RescueError::io(format!("flush {}", path.display()), error))
}

fn collect_file_references(
    payload: &Map<String, Value>,
    references: &mut BTreeMap<String, FileReference>,
) {
    for field in fields(payload) {
        let Some(value) = field.get("value") else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("file") {
            continue;
        }
        let Some(files) = value.get("value").and_then(Value::as_array) else {
            continue;
        };
        for file in files {
            let Some(blob_id) = file.get("blob_id").and_then(Value::as_str) else {
                continue;
            };
            let filename = file
                .get("filename")
                .and_then(Value::as_str)
                .unwrap_or("attachment.bin")
                .to_string();
            references
                .entry(blob_id.to_string())
                .or_insert_with(|| FileReference {
                    filename,
                    mime_type: file
                        .get("mime_type")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    size: file.get("size").and_then(Value::as_u64),
                });
        }
    }
}

fn fields(payload: &Map<String, Value>) -> impl Iterator<Item = &Map<String, Value>> {
    payload
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|group| group.get("fields").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_object)
}

fn string_value(value: &Value) -> Option<String> {
    (value.get("type")?.as_str()? == "string")
        .then(|| value.get("value")?.as_str().map(str::to_string))
        .flatten()
}

fn string_vec_value(value: &Value) -> Option<String> {
    if value.get("type")?.as_str()? != "string_vec" {
        return None;
    }
    Some(
        value
            .get("value")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn totp_value(value: &Value) -> Option<String> {
    if value.get("type")?.as_str()? != "totp" {
        return None;
    }
    let config = value.get("value")?.as_object()?;
    let secret = config.get("secret")?.as_str()?;
    let account = config.get("account")?.as_str()?;
    let issuer = config.get("issuer").and_then(Value::as_str);
    let algorithm = config
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("sha1")
        .to_ascii_uppercase();
    let digits = config.get("digits").and_then(Value::as_u64).unwrap_or(6);
    let period = config.get("period").and_then(Value::as_u64).unwrap_or(30);
    let encoded_account = encode_uri_component(account);
    let label = issuer
        .map(|issuer| format!("{}:{encoded_account}", encode_uri_component(issuer)))
        .unwrap_or(encoded_account);
    let mut uri = format!(
        "otpauth://totp/{label}?secret={secret}&algorithm={algorithm}&digits={digits}&period={period}"
    );
    if let Some(issuer) = issuer {
        uri.push_str("&issuer=");
        uri.push_str(&encode_uri_component(issuer));
    }
    Some(uri)
}

fn encode_uri_component(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn sanitize_filename(value: &str) -> String {
    let value = value
        .chars()
        .map(|character| {
            if character.is_control() || matches!(character, '/' | '\\' | ':') {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
    let value = value.trim().trim_matches('.').trim();
    if value.is_empty() {
        "attachment.bin".to_string()
    } else {
        value.to_string()
    }
}

fn finalize_output(staging: TempDir, output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        return Err(RescueError::OutputExists(output.to_path_buf()));
    }
    if output.exists() {
        validate_previous_export(output)?;
    }

    let staging_path = staging.keep();
    if !output.exists() {
        return fs::rename(&staging_path, output).map_err(|error| {
            RescueError::io(format!("move export to {}", output.display()), error)
        });
    }

    let parent = output_parent(output);
    let backup = tempfile::Builder::new()
        .prefix(".buddy-rescue-previous-")
        .tempdir_in(parent)
        .map_err(|error| RescueError::io("create replacement directory", error))?;
    let backup_path = backup.keep();
    fs::remove_dir(&backup_path)
        .map_err(|error| RescueError::io("prepare replacement directory", error))?;
    fs::rename(output, &backup_path)
        .map_err(|error| RescueError::io("preserve previous export", error))?;

    if let Err(error) = fs::rename(&staging_path, output) {
        let _ = fs::rename(&backup_path, output);
        return Err(RescueError::io(
            format!("move export to {}", output.display()),
            error,
        ));
    }

    fs::remove_dir_all(&backup_path)
        .map_err(|error| RescueError::io("remove replaced export", error))
}

fn validate_previous_export(output: &Path) -> Result<()> {
    if fs::symlink_metadata(output)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(true)
    {
        return Err(RescueError::UnsafeReplacement(output.to_path_buf()));
    }
    if !output.is_dir() {
        return Err(RescueError::UnsafeReplacement(output.to_path_buf()));
    }
    let marker = fs::read(output.join("manifest.json"))
        .map_err(|_| RescueError::UnsafeReplacement(output.to_path_buf()))?;
    let marker: Value = serde_json::from_slice(&marker)
        .map_err(|_| RescueError::UnsafeReplacement(output.to_path_buf()))?;
    if marker.get("format").and_then(Value::as_str) != Some(EXPORT_FORMAT) {
        return Err(RescueError::UnsafeReplacement(output.to_path_buf()));
    }
    Ok(())
}

fn output_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn entry_issue(id: &str, message: String) -> ExportIssue {
    ExportIssue {
        record_type: "entry",
        id: id.to_string(),
        message,
    }
}

fn attachment_issue(id: &str, message: String) -> ExportIssue {
    ExportIssue {
        record_type: "attachment",
        id: id.to_string(),
        message,
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn make_private_file(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn make_private_file(_file: &File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn make_private_path(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn make_private_path(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
