use buddy_crypto_core::{
    Crypto, ENTRY_BLOB_CTX, ENTRY_CTX, KdfParams, create_verifier, derive_subkey, entry_aad,
    entry_blob_envelope_aad, generate_key,
};
use buddy_rescue::{ExportKind, ExportRequest, RescueError, export, inspect};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use zeroize::Zeroizing;

const ENTRY_ID: &str = "22222222-2222-4222-8222-222222222222";
const BLOB_ID: &str = "33333333-3333-4333-8333-333333333333";

struct Fixture {
    _directory: TempDir,
    database: PathBuf,
    attachments: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("buddy.sqlite");
        let attachments = directory.path().join("attachments");
        let connection = Connection::open(&database).unwrap();
        create_schema(&connection);
        insert_vault(
            &connection,
            &attachments,
            "11111111-1111-4111-8111-111111111111",
            "Personal",
            "personal-password",
            "Personal Login",
            "personal-secret",
            b"personal attachment",
            1_700_000_000,
        );
        insert_vault(
            &connection,
            &attachments,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "Work",
            "work-password",
            "Work Login",
            "work-secret",
            b"work attachment",
            1_700_000_100,
        );
        drop(connection);

        Self {
            _directory: directory,
            database,
            attachments,
        }
    }

    fn request(
        &self,
        vault_id: Option<&str>,
        password: &str,
        kind: ExportKind,
        output: &Path,
    ) -> ExportRequest {
        ExportRequest {
            database: self.database.clone(),
            attachments: None,
            vault_id: vault_id.map(str::to_string),
            password: Zeroizing::new(password.to_string()),
            kind,
            output: output.to_path_buf(),
            force: false,
        }
    }
}

#[test]
fn inspect_reports_each_vault_and_scoped_attachment() {
    let fixture = Fixture::new();
    let report = inspect(&fixture.database, None).unwrap();

    assert!(report.compatible);
    assert_eq!(report.schema_version, Some(1));
    assert_eq!(report.vaults.len(), 2);
    for vault in &report.vaults {
        assert_eq!(vault.live_entries, 1);
        assert_eq!(vault.trashed_entries, 0);
        assert_eq!(vault.attachments, 1);
        assert_eq!(vault.attachment_files_present, 1);
        assert_eq!(vault.attachment_files_missing, 0);
    }
}

#[test]
fn export_requires_a_vault_id_when_database_contains_several() {
    let fixture = Fixture::new();
    let output = fixture.database.parent().unwrap().join("export");
    let error =
        export(fixture.request(None, "personal-password", ExportKind::Json, &output)).unwrap_err();

    assert!(matches!(error, RescueError::VaultSelectionRequired(_)));
    assert!(!output.exists());
}

#[test]
fn json_export_uses_only_the_selected_vaults_keys_and_records() {
    let fixture = Fixture::new();
    let vault_id = "11111111-1111-4111-8111-111111111111";
    let output = fixture.database.parent().unwrap().join("json-export");
    let summary = export(fixture.request(
        Some(vault_id),
        "personal-password",
        ExportKind::Json,
        &output,
    ))
    .unwrap();

    assert_eq!(summary.entries, 1);
    assert_eq!(summary.attachments, 1);
    assert_eq!(summary.issues, 0);

    let document: Value =
        serde_json::from_slice(&fs::read(output.join("entries.json")).unwrap()).unwrap();
    assert_eq!(document["vault_id"], vault_id);
    assert_eq!(document["entries"][0]["id"], ENTRY_ID);
    assert_eq!(
        field_value(&document["entries"][0], "title"),
        "Personal Login"
    );
    assert_eq!(
        field_value(&document["entries"][0], "password"),
        "personal-secret"
    );
    assert!(!document.to_string().contains("work-secret"));

    assert_eq!(
        fs::read(
            output
                .join("attachments")
                .join(BLOB_ID)
                .join("recovery.txt")
        )
        .unwrap(),
        b"personal attachment"
    );
}

#[test]
fn csv_export_matches_buddys_compatibility_columns() {
    let fixture = Fixture::new();
    let output = fixture.database.parent().unwrap().join("csv-export");
    let summary = export(fixture.request(
        Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        "work-password",
        ExportKind::Csv,
        &output,
    ))
    .unwrap();

    assert!(summary.warning.is_some());
    let mut reader = csv::Reader::from_path(output.join("entries.csv")).unwrap();
    assert_eq!(
        reader.headers().unwrap().iter().collect::<Vec<_>>(),
        vec![
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
        ]
    );
    let row = reader.records().next().unwrap().unwrap();
    assert_eq!(&row[0], "Work Login");
    assert_eq!(&row[4], "work-secret");
}

#[test]
fn wrong_password_fails_before_creating_output() {
    let fixture = Fixture::new();
    let output = fixture.database.parent().unwrap().join("wrong-password");
    let error = export(fixture.request(
        Some("11111111-1111-4111-8111-111111111111"),
        "wrong",
        ExportKind::Json,
        &output,
    ))
    .unwrap_err();

    assert!(matches!(error, RescueError::InvalidPassword));
    assert!(!output.exists());
}

#[test]
fn missing_attachment_does_not_block_entry_recovery() {
    let fixture = Fixture::new();
    fs::remove_file(
        fixture
            .attachments
            .join("11111111-1111-4111-8111-111111111111")
            .join(BLOB_ID),
    )
    .unwrap();
    let output = fixture.database.parent().unwrap().join("partial-export");
    let summary = export(fixture.request(
        Some("11111111-1111-4111-8111-111111111111"),
        "personal-password",
        ExportKind::Json,
        &output,
    ))
    .unwrap();

    assert_eq!(summary.entries, 1);
    assert_eq!(summary.attachments, 0);
    assert_eq!(summary.issues, 1);
    assert!(output.join("entries.json").is_file());
    let manifest: Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["attachments"][0]["status"], "missing_ciphertext");
}

#[test]
fn command_line_export_reads_the_password_from_standard_input() {
    let fixture = Fixture::new();
    let output = fixture.database.parent().unwrap().join("cli-export");
    let mut child = Command::new(env!("CARGO_BIN_EXE_buddy-rescue"))
        .arg("export")
        .arg(&fixture.database)
        .arg("--vault")
        .arg("11111111-1111-4111-8111-111111111111")
        .arg("--password-stdin")
        .arg("--output")
        .arg(&output)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"personal-password\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(output.join("entries.json").is_file());
}

fn create_schema(connection: &Connection) {
    connection
        .execute_batch(
            "
            CREATE TABLE migrations (
                version INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL
            );
            INSERT INTO migrations (version, created_at) VALUES (1, 1700000000);

            CREATE TABLE vault (
                id TEXT PRIMARY KEY NOT NULL,
                salt BLOB NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                name TEXT NOT NULL,
                color TEXT NULL,
                hint TEXT NULL,
                biometrics_enabled INTEGER NOT NULL,
                kdf_algo TEXT NOT NULL,
                kdf_mem_cost INTEGER NOT NULL,
                kdf_time_cost INTEGER NOT NULL,
                kdf_parallelism INTEGER NOT NULL,
                kdf_version INTEGER NOT NULL,
                password_changed_at INTEGER NOT NULL,
                version INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE entry (
                id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                used_at INTEGER NULL,
                used_count INTEGER NOT NULL,
                deleted_at INTEGER NULL,
                PRIMARY KEY (vault_id, id)
            );

            CREATE TABLE entry_blob (
                id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                entry_id TEXT NULL,
                nonce BLOB NOT NULL,
                envelope_nonce BLOB NOT NULL,
                envelope_ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (vault_id, id)
            );
            ",
        )
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn insert_vault(
    connection: &Connection,
    attachments: &Path,
    vault_id: &str,
    name: &str,
    password: &str,
    title: &str,
    entry_password: &str,
    attachment: &[u8],
    timestamp: i64,
) {
    let kdf = KdfParams {
        algo: "argon2id".to_string(),
        mem_cost: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
        version: 19,
    };
    let (salt, verifier_nonce, verifier_ciphertext, master_key) = create_verifier(password, &kdf);
    connection
        .execute(
            "INSERT INTO vault (
                id, salt, nonce, ciphertext, name, color, hint,
                biometrics_enabled, kdf_algo, kdf_mem_cost, kdf_time_cost,
                kdf_parallelism, kdf_version, password_changed_at, version,
                created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            params![
                vault_id,
                salt,
                verifier_nonce,
                verifier_ciphertext,
                name,
                "#445566",
                kdf.algo,
                kdf.mem_cost,
                kdf.time_cost,
                kdf.parallelism,
                kdf.version,
                timestamp,
                timestamp,
                timestamp,
            ],
        )
        .unwrap();

    let payload = json!({
        "icon": null,
        "groups": [{
            "id": "group",
            "fields": [
                {
                    "id": "title",
                    "role": "title",
                    "name": "Title",
                    "value": {"type": "string", "value": title}
                },
                {
                    "id": "password",
                    "role": "password",
                    "name": "Password",
                    "value": {"type": "string", "value": entry_password}
                },
                {
                    "id": "file",
                    "role": "file",
                    "name": "Files",
                    "value": {
                        "type": "file",
                        "value": [{
                            "blob_id": BLOB_ID,
                            "filename": "recovery.txt",
                            "mime_type": "text/plain",
                            "size": attachment.len()
                        }]
                    }
                }
            ]
        }]
    });
    let entry_key = derive_subkey(&master_key, ENTRY_CTX);
    let (entry_nonce, entry_ciphertext) =
        Crypto::encrypt_with_aad(entry_key, &payload, &entry_aad(vault_id, ENTRY_ID)).unwrap();
    connection
        .execute(
            "INSERT INTO entry (
                id, vault_id, nonce, ciphertext, created_at, updated_at,
                used_at, used_count, deleted_at
             ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, NULL)",
            params![
                ENTRY_ID,
                vault_id,
                entry_nonce,
                entry_ciphertext,
                timestamp,
                timestamp,
            ],
        )
        .unwrap();

    let data_key = generate_key();
    let (content_nonce, content_ciphertext) = Crypto::encrypt_bytes(data_key, attachment).unwrap();
    let blob_key = derive_subkey(&master_key, ENTRY_BLOB_CTX);
    let (envelope_nonce, envelope_ciphertext) = Crypto::encrypt_bytes_with_aad(
        blob_key,
        &data_key,
        &entry_blob_envelope_aad(vault_id, BLOB_ID),
    )
    .unwrap();
    connection
        .execute(
            "INSERT INTO entry_blob (
                id, vault_id, entry_id, nonce, envelope_nonce,
                envelope_ciphertext, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                BLOB_ID,
                vault_id,
                ENTRY_ID,
                content_nonce,
                envelope_nonce,
                envelope_ciphertext,
                timestamp,
                timestamp,
            ],
        )
        .unwrap();

    let directory = attachments.join(vault_id);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(BLOB_ID), content_ciphertext).unwrap();
}

fn field_value<'a>(entry: &'a Value, role: &str) -> &'a str {
    entry["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["fields"].as_array().unwrap())
        .find(|field| field["role"] == role)
        .unwrap()["value"]["value"]
        .as_str()
        .unwrap()
}
