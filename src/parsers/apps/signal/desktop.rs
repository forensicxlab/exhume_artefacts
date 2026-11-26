//! Signal Desktop `db.sqlite` chat parser.
//!
//! Signal Desktop keeps its conversations in a SQLCipher-encrypted
//! `sql/db.sqlite`. This parser reads that file directly when the caller
//! supplies the raw database key (the `database_key` secret option, opened
//! through [`crate::formats::sqlite::sqlcipher`]), and it reads an already
//! decrypted copy as an ordinary SQLite database. It performs no key recovery:
//! obtaining the key from `config.json` and the operating system's keystore is
//! specific to each OS and stays outside the shared database interpretation.
//!
//! The format is the same on every operating system: a `conversations` table
//! and a `messages` table, each with promoted columns plus a `json` blob that
//! holds what Signal does not promote (reactions, edit history, per-recipient
//! send state). Two generations of the schema are read:
//!
//! * attachments live in the `message_attachments` table since Signal Desktop
//!   migration 1360 (2025), and in the message `json` before that;
//! * the author column is `sourceServiceId`, formerly `sourceUuid`, and the
//!   conversation column `serviceId`, formerly `uuid`.
//!
//! Messages are normalised into the canonical `chat.v1` envelope, the same shape
//! the WhatsApp and iMessage parsers emit, so one view serves every chat app.
//!
//! Outgoing receipt flags stay unknown when the owner's conversation cannot be
//! identified. Malformed JSON produces a row-specific `RecordParse` issue while
//! available columns and table-backed attachments remain recoverable. Both
//! diagnostic entry points forward these issues; `run_into` writes them as JSONL
//! to stderr. Diagnostic-handler and stderr-write failures abort parsing.

use crate::core::records::{
    AppInfo, Attachment, ChatMessage, Conversation, Direction, MessageState, Party,
};
use crate::core::{
    CompanionSpec, ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserIssue,
    ParserIssueCode, ParserOptionDefault, ParserOptionSpec, ParserOptionType, ParserOptionValue,
    ParserOptions, TimelineEvent,
};
use crate::formats::sqlite::sqlcipher::{SqlCipherError, SqlCipherKey, SqlCipherProfile};
use crate::formats::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, SqliteStatement, select_column,
    sqlite_source_json,
};
use crate::formats::timestamps::unix_millis_to_json;
use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};

const PARSER_NAME: &str = "desktop_signal";
const APP: AppInfo = AppInfo {
    bundle_id: "org.whispersystems.signal-desktop",
    label: "Signal",
};
const APP_LABEL: &str = "signal";
const SCHEMA_VARIANT: &str = "desktop_signal_db_v1";
/// The database alone does not say which operating system wrote it.
const PLATFORM: &str = "desktop";

/// Message `type` values Signal uses for an actual conversational message.
/// Everything else (`group-v2-change`, `profile-change`, `keychange`, call
/// events, ...) is a system/state row that is not a chat message.
const CHAT_TYPES: &[&str] = &["incoming", "outgoing"];
const TIMER_UPDATE_KIND: &str = "signal.expiration_timer_update";

/// Columns without which a table is not Signal's, whatever its name.
const REQUIRED_COLUMNS: &[(&str, &[&str])] = &[
    ("conversations", &["id", "json"]),
    ("messages", &["id", "type", "conversationId", "json"]),
];

/// Signal `ReadStatus`: `Read = 0`, `Unread = 1`, `Viewed = 2`. Any other value
/// is left undetermined.
fn read_flag(status: Option<i64>) -> Option<bool> {
    match status? {
        0 | 2 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn join_names(given: Option<String>, family: Option<String>) -> Option<String> {
    let parts: Vec<String> = [given, family].into_iter().filter_map(non_empty).collect();
    non_empty(Some(parts.join(" ")))
}

/// `message_attachments.editHistoryIndex` of the current message revision.
const ROOT_EDIT_HISTORY_INDEX: i64 = -1;

const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

const DATABASE_KEY: &str = "database_key";
const CIPHER_VERSION: &str = "cipher_version";

/// Same names and meaning as the SQLCipher inspection example, so a key that
/// passes there is passed here unchanged.
const OPTIONS: &[ParserOptionSpec] = &[
    ParserOptionSpec {
        name: DATABASE_KEY,
        label: "Database key",
        description: "Raw SQLCipher database key: exactly 64 hexadecimal characters. \
                      Only needed when db.sqlite is still encrypted",
        value_type: ParserOptionType::Secret,
        // Conditional: requested at run time, and only for an encrypted input.
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: CIPHER_VERSION,
        label: "SQLCipher compatibility version",
        description: "Standard SQLCipher settings: 4 (current Signal Desktop) or 3 \
                      (database never opened by a release using SQLCipher 4)",
        value_type: ParserOptionType::Integer,
        required: false,
        default: Some(ParserOptionDefault::Integer(4)),
    },
];

/// A conversation, as the parser needs it while normalising messages.
#[derive(Clone, Default)]
struct ConvInfo {
    rowid: Option<i64>,
    /// The title Signal shows: nickname, contact or group name, profile name,
    /// then username.
    name: Option<String>,
    /// Name from the owner's address book, or the title of a group.
    contact_name: Option<String>,
    /// Given and family name the account publishes in its profile.
    profile_name: Option<String>,
    /// Nickname the owner gave this contact inside Signal.
    nickname: Option<String>,
    username: Option<String>,
    conv_type: Option<String>,
    service_id: Option<String>,
    e164: Option<String>,
    group_id: Option<String>,
    active_at: Option<i64>,
    expire_timer_seconds: Option<i64>,
    expire_timer_version: Option<i64>,
    /// UI preview metadata can survive removal of the referenced message row.
    /// Preserve it as a cache, never synthesize a message or receipt from it.
    last_message_cache: Value,
    /// Service ids of the group members (empty for a one-to-one conversation).
    member_ids: Vec<String>,
}

/// Everything known about the conversations of one database.
struct Directory {
    /// Keyed by conversation id; ordered so the output is deterministic.
    conversations: BTreeMap<String, ConvInfo>,
    /// Service id (ACI) to the display name of that contact.
    names: HashMap<String, String>,
    /// The device owner's service id, from `items.uuid_id`.
    me: Option<String>,
    /// The device owner's own conversation ("Note to Self").
    own_conversation: Option<String>,
}

/// Read status of the revisions of edited messages, from `edited_messages`:
/// `(message id, revision sent_at)` to `readStatus`.
type EditReadStatus = HashMap<(String, i64), i64>;

impl Directory {
    fn party(&self, service_id: &str) -> Party {
        Party {
            id: Some(service_id.to_owned()),
            display_name: self.names.get(service_id).cloned(),
            is_self: self.me.as_deref() == Some(service_id),
        }
    }

    fn participants(&self, conv: &ConvInfo) -> Vec<Party> {
        if !conv.member_ids.is_empty() {
            return conv.member_ids.iter().map(|id| self.party(id)).collect();
        }
        match conv.service_id.as_deref() {
            Some(id) => vec![self.party(id)],
            None => Vec::new(),
        }
    }
}

/// Columns of `message_attachments` reported verbatim, beside the ones the
/// parser interprets: `(column, key in the output)`.
const ATTACHMENT_TEXT_COLUMNS: &[(&str, &str)] = &[
    ("clientUuid", "client_uuid"),
    ("blurHash", "blur_hash"),
    ("digest", "digest"),
    ("key", "key"),
    ("incrementalMac", "incremental_mac"),
    ("downloadPath", "download_path"),
    ("localBackupPath", "local_backup_path"),
    ("transitCdnKey", "transit_cdn_key"),
    ("thumbnailContentType", "thumbnail_content_type"),
    ("thumbnailLocalKey", "thumbnail_local_key"),
    ("screenshotPath", "screenshot_path"),
    ("screenshotContentType", "screenshot_content_type"),
    ("screenshotLocalKey", "screenshot_local_key"),
    ("backupThumbnailPath", "backup_thumbnail_path"),
    (
        "backupThumbnailContentType",
        "backup_thumbnail_content_type",
    ),
    ("backupThumbnailLocalKey", "backup_thumbnail_local_key"),
    ("storyTextAttachmentJson", "story_text_attachment_json"),
];
const ATTACHMENT_INTEGER_COLUMNS: &[(&str, &str)] = &[
    ("version", "version"),
    ("incrementalMacChunkSize", "incremental_mac_chunk_size"),
    ("transitCdnNumber", "transit_cdn_number"),
    ("transitCdnUploadTimestamp", "transit_cdn_upload_timestamp"),
    ("backupCdnNumber", "backup_cdn_number"),
    ("thumbnailSize", "thumbnail_size"),
    ("thumbnailVersion", "thumbnail_version"),
    ("screenshotSize", "screenshot_size"),
    ("screenshotVersion", "screenshot_version"),
    ("backupThumbnailSize", "backup_thumbnail_size"),
    ("backupThumbnailVersion", "backup_thumbnail_version"),
    ("flags", "flags"),
    ("error", "error"),
    ("wasTooBig", "was_too_big"),
    ("isCorrupted", "is_corrupted"),
    (
        "copiedFromQuotedAttachment",
        "copied_from_quoted_attachment",
    ),
    ("pending", "pending"),
    ("backfillError", "backfill_error"),
    ("isViewOnce", "is_view_once"),
    ("transcodingTargetQuality", "transcoding_target_quality"),
];

/// Directory of the Signal profile that `path` and `thumbnailPath` are
/// relative to. The database itself sits in the sibling `sql` directory.
const ATTACHMENTS_DIRECTORY: &str = "attachments.noindex";

/// One attachment row, whichever generation of the schema stored it.
struct SignalAttachment {
    /// Row in `message_attachments`; none for an attachment kept in the
    /// message `json`.
    rowid: Option<i64>,
    /// `attachment`, `long-message`, `quote`, `preview`, `contact` or `sticker`.
    attachment_type: String,
    order: Option<i64>,
    content_type: Option<String>,
    file_name: Option<String>,
    /// As recorded: relative to the profile's `attachments.noindex` directory.
    path: Option<String>,
    size: Option<i64>,
    /// Key Signal encrypts the file on disk with (base64), when it does.
    local_key: Option<String>,
    plaintext_hash: Option<String>,
    caption: Option<String>,
    width: Option<i64>,
    height: Option<i64>,
    /// Seconds, for audio and video.
    duration: Option<f64>,
    thumbnail_path: Option<String>,
    /// What else the database records about it, as stored: the other columns
    /// that hold a value, or the whole entry of the message `json`.
    recorded: Vec<(&'static str, Value)>,
}

impl SignalAttachment {
    fn to_canonical(&self) -> Attachment {
        Attachment {
            kind: Some(attachment_kind(
                &self.attachment_type,
                self.content_type.as_deref(),
            )),
            filename: self.file_name.clone(),
            local_path: self.path.clone(),
            mime: self.content_type.clone(),
            size_bytes: self.size,
        }
    }

    fn to_details(&self) -> Value {
        let mut details = Map::new();
        for (key, value) in [
            ("rowid", json!(self.rowid)),
            ("attachment_type", json!(self.attachment_type)),
            ("order_in_message", json!(self.order)),
            ("content_type", json!(self.content_type)),
            ("file_name", json!(self.file_name)),
            ("path", json!(self.path)),
            ("size", json!(self.size)),
            ("local_key", json!(self.local_key)),
            ("plaintext_hash", json!(self.plaintext_hash)),
            ("caption", json!(self.caption)),
            ("width", json!(self.width)),
            ("height", json!(self.height)),
            ("duration", json!(self.duration)),
            ("thumbnail_path", json!(self.thumbnail_path)),
        ] {
            details.insert(key.to_owned(), value);
        }
        for (key, value) in &self.recorded {
            details.insert((*key).to_owned(), value.clone());
        }
        Value::Object(details)
    }

    /// Whether the row is a file of the message itself. Quote thumbnails, link
    /// previews, shared-contact avatars and the overflow of a long text are
    /// attachment rows too, but belong to the message content.
    fn is_message_file(&self) -> bool {
        matches!(self.attachment_type.as_str(), "attachment" | "sticker")
    }

    /// Text shown and searched for the attachment record.
    fn label(&self) -> String {
        [&self.file_name, &self.caption, &self.path]
            .into_iter()
            .find_map(|value| non_empty(value.clone()))
            .unwrap_or_else(|| attachment_kind(&self.attachment_type, self.content_type.as_deref()))
    }
}

/// The opened evidence copy and how it was opened.
struct Store<'a> {
    evidence: &'a SqliteEvidence,
    /// The SQLCipher settings the database was opened with; none for a
    /// database that was already decrypted.
    cipher: Option<SqlCipherProfile>,
}

impl Store<'_> {
    fn source(&self, table: &str, id: Option<&str>, rowid: Option<i64>) -> Value {
        let mut source = sqlite_source_json(
            self.evidence,
            table,
            rowid.unwrap_or_default(),
            SCHEMA_VARIANT,
        );
        source["id"] = json!(id);
        source["rowid"] = json!(rowid);
        source["cipher_profile"] = json!(self.cipher);
        source
    }

    /// Decode an optional JSON column without hiding a damaged source record.
    /// Only locations and error categories are reported, never the JSON content.
    fn parse_json(
        &self,
        table: &str,
        id: Option<&str>,
        rowid: Option<i64>,
        text: Option<String>,
        diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<Value> {
        let Some(text) = text else {
            return Ok(Value::Null);
        };
        match serde_json::from_str(&text) {
            Ok(value) => Ok(value),
            Err(error) => {
                let location = match rowid {
                    Some(rowid) => format!("rowid {rowid}"),
                    None => format!("id {:?}", id.unwrap_or("<unknown>")),
                };
                diagnostic(ParserIssue {
                    code: ParserIssueCode::RecordParse,
                    unit: rowid.and_then(|rowid| u64::try_from(rowid).ok()),
                    message: format!(
                        "{}: malformed {table}.json at {location} ({:?} at line {}, column {}); \
                         JSON-only fields may be incomplete",
                        self.evidence.source_label(),
                        error.classify(),
                        error.line(),
                        error.column(),
                    ),
                })?;
                Ok(Value::Null)
            }
        }
    }
}

/// What an attachment record repeats about the message it belongs to.
struct MessageContext<'a> {
    rowid: Option<i64>,
    id: Option<&'a str>,
    signal_type: &'a str,
    content_kind: &'a str,
    body: Option<&'a str>,
    direction: Direction,
    sender: &'a Party,
    conversation_id: &'a str,
    conversation: &'a ConvInfo,
    sent_at: Option<i64>,
    received_at: Option<i64>,
}

/// Map a Signal attachment onto the envelope's `image | video | audio |
/// document | sticker | contact | unknown` vocabulary.
fn attachment_kind(attachment_type: &str, content_type: Option<&str>) -> String {
    let kind = match attachment_type {
        "sticker" => "sticker",
        "contact" => "contact",
        _ => match content_type {
            Some(mime) if mime.starts_with("image/") => "image",
            Some(mime) if mime.starts_with("video/") => "video",
            Some(mime) if mime.starts_with("audio/") => "audio",
            Some(_) => "document",
            None => "unknown",
        },
    };
    kind.to_owned()
}

#[derive(Default)]
pub struct SignalDesktopParser;

impl Parser for SignalDesktopParser {
    fn attachment_recipe(
        &self,
        record: &Value,
        rendition: crate::assets::Rendition,
    ) -> crate::assets::Result<Option<Box<dyn crate::assets::AssetRecipe>>> {
        crate::recovery::signal::attachment::AttachmentSpec::from_record(record, rendition)
            .map(|spec| Some(Box::new(spec) as Box<dyn crate::assets::AssetRecipe>))
    }
    fn asset_root(&self, primary_path: &std::path::Path) -> Option<std::path::PathBuf> {
        let sql = primary_path
            .parent()
            .filter(|path| path.file_name().is_some_and(|name| name == "sql"))?;
        sql.parent().map(std::path::Path::to_path_buf)
    }

    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse a Signal Desktop db.sqlite (decrypted, or SQLCipher with its database key): \
         conversations, messages, attachments, reactions."
    }

    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        OPTIONS
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        let event_type = match obj.kind {
            "mobile.communication.message" => "mobile.communication.message",
            "mobile.communication.attachment" => "mobile.communication.attachment",
            TIMER_UPDATE_KIND => TIMER_UPDATE_KIND,
            _ => return Vec::new(),
        };
        let Some(ts_unix_ms) = obj.json["timestamps"]["message"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        // `text` is the body, or the attachment name for a media-only message
        // and for an attachment record.
        let description = Some(obj.text.clone()).filter(|text| !text.is_empty());
        let actor = if obj.kind == TIMER_UPDATE_KIND {
            obj.json["actor"]["service_id"].as_str().map(str::to_owned)
        } else {
            obj.json["sender"]["id"].as_str().map(str::to_owned)
        };
        vec![TimelineEvent {
            ts_unix_ms,
            event_type,
            description,
            actor,
        }]
    }

    /// Without options a decrypted database is parsed as is, and an encrypted
    /// one answers with a request for `database_key`.
    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        self.run_into_with_diagnostics(input, sink, &mut |issue| {
            use std::io::Write;
            writeln!(
                std::io::stderr().lock(),
                "{}",
                serde_json::to_string(&issue)?
            )?;
            Ok(())
        })
    }

    fn run_into_with_diagnostics(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        crate::run_parser_with_options(self, input, ParserOptions::default(), sink, diagnostic)
    }

    fn run_into_with_context(
        &self,
        input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        if context.parser_name() != PARSER_NAME {
            return Err(ParserInputError::invalid("context", "parser context mismatch").into());
        }
        let profile = cipher_profile(context)?;
        let evidence = SqliteEvidence::from_input(input, "db.sqlite")?;
        // Everything that can ask for input or refuse the database happens
        // here, before the first record, so the caller can retry safely.
        let (conn, cipher) = open_database(&evidence, context, profile)?;
        let schema = conn.schema()?;

        let missing: Vec<&str> = ["conversations", "messages"]
            .into_iter()
            .filter(|table| !schema.has_table(table))
            .collect();
        if !missing.is_empty() {
            anyhow::bail!(
                "not a Signal Desktop database: missing table(s) {}",
                missing.join(", ")
            );
        }

        for (table, columns) in REQUIRED_COLUMNS {
            let missing = schema.missing_columns(table, columns);
            if !missing.is_empty() {
                anyhow::bail!(
                    "not a Signal Desktop database: missing column(s) {}",
                    missing.join(", ")
                );
            }
        }

        let store = Store {
            evidence: &evidence,
            cipher,
        };
        let directory = load_directory(&conn, &schema, &store, diagnostic)?;
        let edits = load_edit_read_status(&conn, &schema)?;

        // Compiled once before the first record: a table this query cannot
        // read must not surface after the conversations are out.
        conn.query_rows(&format!("EXPLAIN {}", message_query(&schema)), |_| Ok(()))
            .context("cannot read the messages of this database")?;

        emit_conversations(&directory, &store, sink)?;
        emit_messages(&conn, &schema, &store, &directory, &edits, sink, diagnostic)
    }
}

fn cipher_profile(context: &ParserContext) -> Result<SqlCipherProfile, ParserInputError> {
    match context.option(CIPHER_VERSION) {
        Some(ParserOptionValue::Integer(3)) => Ok(SqlCipherProfile::SqlCipher3),
        Some(ParserOptionValue::Integer(4)) => Ok(SqlCipherProfile::SqlCipher4),
        _ => Err(ParserInputError::invalid(CIPHER_VERSION, "expected 3 or 4")),
    }
}

/// Open the evidence copy as plain SQLite when it starts with the SQLite
/// header, and through SQLCipher with the caller's key otherwise.
///
/// A file without that header is not known to be encrypted: it may also be
/// damaged or not a database. The key request says what would be needed if it
/// is, and a failed open keeps the backend's own error, which does not single
/// out the key: the cipher settings or the evidence can be responsible too.
fn open_database(
    evidence: &SqliteEvidence,
    context: &ParserContext,
    profile: SqlCipherProfile,
) -> Result<(SqliteConnection, Option<SqlCipherProfile>)> {
    match leading_bytes(evidence.path())? {
        Leading::SqliteHeader => {
            if context.secret(DATABASE_KEY).is_some() {
                log::debug!(
                    "{}: plain SQLite database, {DATABASE_KEY} not used",
                    evidence.source_label()
                );
            }
            Ok((SqliteConnection::open(evidence.path())?, None))
        }
        Leading::Nothing => anyhow::bail!("{} is empty", evidence.source_label()),
        Leading::Fragment => anyhow::bail!(
            "{} is smaller than one database page and does not start with the SQLite header",
            evidence.source_label()
        ),
        Leading::Other => {
            // A key cannot help a build that has no SQLCipher backend.
            if !cfg!(feature = "sqlcipher") {
                return Err(
                    anyhow::Error::new(SqlCipherError::Unavailable).context(format!(
                        "{} does not start with the SQLite header and is probably still encrypted",
                        evidence.source_label()
                    )),
                );
            }
            let key = SqlCipherKey::from_hex(context.require_secret(DATABASE_KEY)?)
                .map_err(|error| ParserInputError::invalid(DATABASE_KEY, error.to_string()))?;
            let conn = SqliteConnection::open_encrypted(evidence.path(), &key, profile)?;
            Ok((conn, Some(profile)))
        }
    }
}

enum Leading {
    SqliteHeader,
    Nothing,
    /// Shorter than the smallest page SQLite or SQLCipher writes.
    Fragment,
    Other,
}

/// SQLCipher encrypts the whole first page, so an encrypted database does not
/// start with the SQLite magic.
fn leading_bytes(path: &std::path::Path) -> Result<Leading> {
    use std::io::Read;
    const MAGIC: &[u8; 16] = b"SQLite format 3\0";
    const SMALLEST_PAGE: u64 = 512;
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    let mut start = Vec::with_capacity(MAGIC.len());
    file.take(MAGIC.len() as u64).read_to_end(&mut start)?;
    Ok(match start.as_slice() {
        [] => Leading::Nothing,
        start if start == MAGIC => Leading::SqliteHeader,
        _ if size < SMALLEST_PAGE => Leading::Fragment,
        _ => Leading::Other,
    })
}

/// `items` row `uuid_id` carries the device owner's service id (ACI), stored
/// as `<aci>.<device id>`.
fn device_owner_service_id(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    store: &Store,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<Option<String>> {
    if !schema.missing_columns("items", &["id", "json"]).is_empty() {
        return Ok(None);
    }
    let mut owner = None;
    // The item key identifies the source even in an items table WITHOUT ROWID.
    // Missing/malformed identity leaves the owner unknown; operational and
    // diagnostic-handler failures still propagate.
    conn.query_rows("SELECT json FROM items WHERE id = 'uuid_id';", |row| {
        let value = store.parse_json("items", Some("uuid_id"), None, row.text(0), diagnostic)?;
        if let Some(id) = value["value"].as_str() {
            owner = id.split('.').next().map(str::to_owned);
        }
        Ok(())
    })?;
    Ok(owner.filter(|id| !id.is_empty()))
}

fn load_directory(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    store: &Store,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<Directory> {
    const T: &str = "conversations";
    let column = |name: &str, alias: &str| select_column(schema, T, "c", name, alias);
    let sql = format!(
        "SELECT c.rowid AS row_id, c.id AS id, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} \
         FROM conversations c ORDER BY c.rowid;",
        column("json", "json"),
        column("type", "conv_type"),
        column("serviceId", "service_id"),
        column("uuid", "legacy_uuid"),
        column("e164", "e164"),
        column("groupId", "group_id"),
        column("active_at", "active_at"),
        column("name", "name"),
        column("profileName", "profile_name"),
        column("profileFamilyName", "profile_family_name"),
        column("profileFullName", "profile_full_name"),
    );

    let me = device_owner_service_id(conn, schema, store, diagnostic)?;
    let mut conversations = BTreeMap::new();
    let mut names = HashMap::new();
    let mut own_conversation = None;

    conn.query_rows(&sql, |row| {
        let id = row.text(1);
        let blob = store.parse_json(T, id.as_deref(), row.i64(0), row.text(2), diagnostic)?;
        let Some(id) = id else {
            return Ok(());
        };
        let text_of = |key: &str| non_empty(blob[key].as_str().map(str::to_owned));

        let service_id = non_empty(row.text(4))
            .or_else(|| non_empty(row.text(5)))
            .or_else(|| text_of("serviceId"))
            .or_else(|| text_of("uuid"));
        let e164 = text_of("e164").or_else(|| non_empty(row.text(6)));
        let contact_name = text_of("name").or_else(|| non_empty(row.text(9)));
        // `profileFullName` only exists as a column; the blob keeps the parts.
        let profile_name = non_empty(row.text(12)).or_else(|| {
            join_names(
                text_of("profileName").or_else(|| row.text(10)),
                text_of("profileFamilyName").or_else(|| row.text(11)),
            )
        });
        let nickname = join_names(text_of("nicknameGivenName"), text_of("nicknameFamilyName"));
        let username = text_of("username");
        let name = [&nickname, &contact_name, &profile_name, &username]
            .into_iter()
            .find_map(Clone::clone);

        if let Some(service_id) = &service_id {
            if me.as_deref() == Some(service_id.as_str()) {
                own_conversation = Some(id.clone());
            }
            if let Some(name) = name.clone().or_else(|| e164.clone()) {
                names.insert(service_id.clone(), name);
            }
        }

        conversations.insert(
            id,
            ConvInfo {
                rowid: row.i64(0),
                name,
                contact_name,
                profile_name,
                nickname,
                username,
                conv_type: row.text(3).or_else(|| text_of("type")),
                service_id,
                e164,
                group_id: text_of("groupId").or_else(|| non_empty(row.text(7))),
                active_at: row.i64(8),
                expire_timer_seconds: blob["expireTimer"].as_i64(),
                expire_timer_version: blob["expireTimerVersion"].as_i64(),
                last_message_cache: blob.get("lastMessage").map_or(Value::Null, |_| json!({
                    "text": blob["lastMessage"].as_str(),
                    "status": blob["lastMessageStatus"].as_str(),
                    "author": blob["lastMessageAuthor"].as_str(),
                    "author_service_id": blob["lastMessageAuthorAci"].as_str(),
                    "deleted_for_everyone": blob["lastMessageDeletedForEveryone"].as_bool(),
                    // received_at is Signal's ordering counter; only the Ms
                    // field is interpreted as an epoch-millisecond timestamp.
                    "received_at_counter": blob["lastMessageReceivedAt"].as_i64(),
                    "received_at": unix_millis_to_json(blob["lastMessageReceivedAtMs"].as_i64()),
                })),
                member_ids: group_member_ids(&blob),
            },
        );
        Ok(())
    })?;

    Ok(Directory {
        conversations,
        names,
        me,
        own_conversation,
    })
}

/// Read status Signal keeps per revision of an edited message. Reading an edit
/// updates this table, not the `readStatus` column of the message.
fn load_edit_read_status(conn: &SqliteConnection, schema: &SqliteSchema) -> Result<EditReadStatus> {
    const T: &str = "edited_messages";
    let mut edits = EditReadStatus::new();
    if !schema
        .missing_columns(T, &["messageId", "sentAt", "readStatus"])
        .is_empty()
    {
        return Ok(edits);
    }
    conn.query_rows(
        "SELECT e.messageId, e.sentAt, e.readStatus FROM edited_messages e;",
        |row| {
            if let (Some(id), Some(sent_at), Some(status)) = (row.text(0), row.i64(1), row.i64(2)) {
                edits.insert((id, sent_at), status);
            }
            Ok(())
        },
    )?;
    Ok(edits)
}

/// Group membership, from `membersV2` (objects carrying an `aci`) or the older
/// `members` (plain ids).
fn group_member_ids(blob: &Value) -> Vec<String> {
    let members = blob["membersV2"]
        .as_array()
        .or_else(|| blob["members"].as_array());
    members
        .map(|members| {
            members
                .iter()
                .filter_map(|member| {
                    member["aci"]
                        .as_str()
                        .or_else(|| member["serviceId"].as_str())
                        .or_else(|| member["uuid"].as_str())
                        .or_else(|| member.as_str())
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Columns of `message_attachments` the parser interprets, in the order they
/// are selected; the ones reported verbatim follow.
const ATTACHMENT_INTERPRETED_COLUMNS: &[&str] = &[
    "attachmentType",
    "orderInMessage",
    "contentType",
    "fileName",
    "path",
    "size",
    "localKey",
    "plaintextHash",
    "caption",
    "width",
    "height",
    "duration",
    "thumbnailPath",
];

/// The select list and the join that bring the attachments of the current
/// revision of a message next to its row, from the `message_attachments` table
/// (absent before migration 1360). A message with several attachments comes
/// back once per attachment, so nothing is held in memory but the message
/// being read.
fn attachment_join(schema: &SqliteSchema) -> Option<(String, String)> {
    const TABLE: &str = "message_attachments";
    if !schema.has_column(TABLE, "messageId") {
        return None;
    }
    let verbatim = ATTACHMENT_TEXT_COLUMNS
        .iter()
        .chain(ATTACHMENT_INTEGER_COLUMNS)
        .map(|(column, _)| column);
    let columns: Vec<String> = ATTACHMENT_INTERPRETED_COLUMNS
        .iter()
        .chain(verbatim)
        .enumerate()
        .map(|(index, column)| select_column(schema, TABLE, "a", column, &format!("a{index}")))
        .collect();
    let revision_filter = if schema.has_column(TABLE, "editHistoryIndex") {
        format!("AND a.editHistoryIndex = {ROOT_EDIT_HISTORY_INDEX}")
    } else {
        String::new()
    };
    // `messages.id` is declared STRING, which SQLite gives NUMERIC affinity,
    // and a comparison with that column cannot use the index of the TEXT
    // column `messageId`: every message would scan the whole table. Compared
    // with a text value, the lookup goes through the primary key.
    Some((
        format!("a.rowid AS attachment_row_id, {}", columns.join(", ")),
        format!("LEFT JOIN {TABLE} a ON a.messageId = CAST(m.id AS TEXT) {revision_filter}"),
    ))
}

/// The attachment joined to this row, if there is one; `first` is the index of
/// its row id.
fn joined_attachment(row: &SqliteStatement<'_>, first: i32) -> Option<SignalAttachment> {
    let rowid = row.i64(first)?;
    let column = |offset: i32| first + 1 + offset;
    // Most of the verbatim columns are empty on most rows; keep what is set.
    let mut recorded = Vec::new();
    let mut index = column(ATTACHMENT_INTERPRETED_COLUMNS.len() as i32);
    for (_, key) in ATTACHMENT_TEXT_COLUMNS {
        if let Some(value) = row.text(index) {
            recorded.push((*key, Value::String(value)));
        }
        index += 1;
    }
    for (_, key) in ATTACHMENT_INTEGER_COLUMNS {
        if let Some(value) = row.i64(index) {
            recorded.push((*key, json!(value)));
        }
        index += 1;
    }
    Some(SignalAttachment {
        rowid: Some(rowid),
        attachment_type: row
            .text(column(0))
            .unwrap_or_else(|| "attachment".to_owned()),
        order: row.i64(column(1)),
        content_type: row.text(column(2)),
        file_name: row.text(column(3)),
        path: row.text(column(4)),
        size: row.i64(column(5)),
        local_key: row.text(column(6)),
        plaintext_hash: row.text(column(7)),
        caption: row.text(column(8)),
        width: row.i64(column(9)),
        height: row.i64(column(10)),
        duration: row.f64(column(11)),
        thumbnail_path: row.text(column(12)),
        recorded,
    })
}

/// Attachments Signal kept inline in the message `json` before migration 1360:
/// the `attachments` list and the image of a sticker.
fn json_attachments(blob: &Value) -> Vec<SignalAttachment> {
    let from_json = |attachment_type: &str, order: usize, item: &Value| {
        let text_of = |key: &str| item[key].as_str().map(str::to_owned);
        SignalAttachment {
            rowid: None,
            attachment_type: attachment_type.to_owned(),
            order: i64::try_from(order).ok(),
            content_type: text_of("contentType"),
            file_name: text_of("fileName"),
            path: text_of("path"),
            size: item["size"].as_i64(),
            local_key: text_of("localKey"),
            plaintext_hash: text_of("plaintextHash"),
            caption: text_of("caption"),
            width: item["width"].as_i64(),
            height: item["height"].as_i64(),
            duration: item["duration"].as_f64(),
            thumbnail_path: item["thumbnail"]["path"].as_str().map(str::to_owned),
            // No columns here: the entry is the record.
            recorded: vec![("inline_json", item.clone())],
        }
    };
    let mut attachments: Vec<SignalAttachment> = blob["attachments"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item.is_object())
                .enumerate()
                .map(|(index, item)| from_json("attachment", index, item))
                .collect()
        })
        .unwrap_or_default();
    if blob["sticker"]["data"].is_object() {
        attachments.push(from_json("sticker", 0, &blob["sticker"]["data"]));
    }
    attachments
}

fn emit_conversations(
    directory: &Directory,
    store: &Store,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    for (id, conv) in &directory.conversations {
        let json = json!({
            "platform": PLATFORM,
            "app": APP_LABEL,
            "record_type": "chat",
            "source": store.source("conversations", Some(id), conv.rowid),
            "chat": {
                "rowid": conv.rowid,
                "id": id,
                "name": conv.name,
                "contact_name": conv.contact_name,
                "profile_name": conv.profile_name,
                "nickname": conv.nickname,
                "username": conv.username,
                "type": conv.conv_type,
                "service_id": conv.service_id,
                "e164": conv.e164,
                "group_id": conv.group_id,
                "is_self": directory.own_conversation.as_deref() == Some(id.as_str()),
                "disappearing_messages": {
                    "expire_timer_seconds": conv.expire_timer_seconds,
                    "expire_timer_version": conv.expire_timer_version,
                },
                "last_message_cache": conv.last_message_cache,
                "participants": directory
                    .participants(conv)
                    .iter()
                    .map(Party::to_json)
                    .collect::<Vec<_>>(),
            },
            "timestamps": {
                "last_active": unix_millis_to_json(conv.active_at),
            },
        });
        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.communication.chat",
            text: conv.name.clone().unwrap_or_else(|| id.clone()),
            json,
        })?;
    }
    Ok(())
}

/// The promoted columns of one `messages` row, in the order they are selected.
struct MessageRow {
    rowid: Option<i64>,
    id: Option<String>,
    message_type: String,
    conversation_id: String,
    json: Option<String>,
    body: Option<String>,
    sent_at: Option<i64>,
    received_at_ms: Option<i64>,
    read_status: Option<i64>,
    seen_status: Option<i64>,
    is_erased: Option<bool>,
    source_service_id: Option<String>,
    legacy_source_uuid: Option<String>,
    source_e164: Option<String>,
    source_device: Option<i64>,
    is_view_once: Option<bool>,
    expire_timer: Option<i64>,
    expiration_start: Option<i64>,
    story_id: Option<String>,
}

/// Number of columns selected from `messages`; the joined attachment follows.
const MESSAGE_COLUMNS: i32 = 19;

/// One row per message, or per attachment of the current revision of a
/// message, the rows of one message being consecutive.
fn message_query(schema: &SqliteSchema) -> String {
    const T: &str = "messages";
    let column = |name: &str, alias: &str| select_column(schema, T, "m", name, alias);
    let (attachment_columns, join) = match attachment_join(schema) {
        Some((columns, join)) => (format!(", {columns}"), join),
        None => (String::new(), String::new()),
    };
    // Ordered by message only: its attachments are put in order once they
    // are all read.
    format!(
        "SELECT m.rowid AS row_id, m.id AS id, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, \
         {}, {}, {}, {}, {}{attachment_columns} FROM messages m {join} ORDER BY m.rowid;",
        column("type", "message_type"),
        column("conversationId", "conversation_id"),
        column("json", "json"),
        column("body", "body"),
        column("sent_at", "sent_at"),
        column("received_at_ms", "received_at_ms"),
        column("readStatus", "read_status"),
        column("seenStatus", "seen_status"),
        column("isErased", "is_erased"),
        column("sourceServiceId", "source_service_id"),
        column("sourceUuid", "legacy_source_uuid"),
        column("source", "source_e164"),
        column("sourceDevice", "source_device"),
        column("isViewOnce", "is_view_once"),
        column("expireTimer", "expire_timer"),
        column("expirationStartTimestamp", "expiration_start"),
        column("storyId", "story_id"),
    )
}

fn emit_messages(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    store: &Store,
    directory: &Directory,
    edits: &EditReadStatus,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<()> {
    let has_join = attachment_join(schema).is_some();
    let sql = message_query(schema);

    // The message being read and the attachments joined to it so far.
    let mut pending: Option<(MessageRow, Vec<SignalAttachment>)> = None;
    conn.query_rows(&sql, |row| {
        let rowid = row.i64(0);
        if pending
            .as_ref()
            .is_none_or(|(message, _)| message.rowid != rowid)
        {
            if let Some((message, attachments)) = pending.take() {
                emit_message(
                    store,
                    directory,
                    edits,
                    message,
                    attachments,
                    sink,
                    diagnostic,
                )?;
            }
            let message_type = row.text(2).unwrap_or_default();
            if !CHAT_TYPES.contains(&message_type.as_str()) && message_type != "timer-notification"
            {
                return Ok(());
            }
            pending = Some((
                MessageRow {
                    rowid,
                    id: row.text(1),
                    message_type,
                    conversation_id: row.text(3).unwrap_or_default(),
                    json: row.text(4),
                    body: row.text(5),
                    sent_at: row.i64(6),
                    received_at_ms: row.i64(7),
                    read_status: row.i64(8),
                    seen_status: row.i64(9),
                    is_erased: row.bool(10),
                    source_service_id: row.text(11),
                    legacy_source_uuid: row.text(12),
                    source_e164: row.text(13),
                    source_device: row.i64(14),
                    is_view_once: row.bool(15),
                    expire_timer: row.i64(16),
                    expiration_start: row.i64(17),
                    story_id: row.text(18),
                },
                Vec::new(),
            ));
        }
        if has_join
            && let Some((_, attachments)) = pending.as_mut()
            && let Some(attachment) = joined_attachment(row, MESSAGE_COLUMNS)
        {
            attachments.push(attachment);
        }
        Ok(())
    })?;
    match pending {
        Some((message, attachments)) => emit_message(
            store,
            directory,
            edits,
            message,
            attachments,
            sink,
            diagnostic,
        ),
        None => Ok(()),
    }
}

/// Normalise one chat message and emit it, followed by one record per file.
fn emit_message(
    store: &Store,
    directory: &Directory,
    edits: &EditReadStatus,
    row: MessageRow,
    mut table_attachments: Vec<SignalAttachment>,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<()> {
    const T: &str = "messages";
    let message_type = row.message_type;
    let rowid = row.rowid;
    let message_id = row.id;
    let conversation_id = row.conversation_id;
    let blob = store.parse_json(T, message_id.as_deref(), rowid, row.json, diagnostic)?;
    let text_of = |key: &str| blob[key].as_str().map(str::to_owned);

    let unknown_conversation = ConvInfo::default();
    let conv = directory
        .conversations
        .get(&conversation_id)
        .unwrap_or(&unknown_conversation);
    // Native Signal stores timer changes as system rows. Preserve the setting
    // and its timestamp without assigning a chat-message direction or receipts.
    if message_type == "timer-notification" {
        let update = &blob["expirationTimerUpdate"];
        let seconds = update["expireTimer"].as_i64();
        let text = match seconds {
            Some(0) => "Disappearing messages disabled".to_string(),
            Some(seconds) if seconds > 0 => format!("Disappearing messages: {seconds} seconds"),
            _ => "Disappearing messages timer update".to_string(),
        };
        return sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: TIMER_UPDATE_KIND,
            text,
            json: json!({
                "platform": PLATFORM, "app": APP_LABEL,
                "record_type": "expiration_timer_update",
                "source": store.source(T, message_id.as_deref(), rowid),
                "chat": { "id": conversation_id, "name": conv.name },
                "actor": {
                    "service_id": update["sourceServiceId"].as_str().or(row.source_service_id.as_deref()),
                    "conversation_id": update["source"],
                },
                "timestamps": {
                    "message": unix_millis_to_json(row.sent_at.or_else(|| blob["sent_at"].as_i64())),
                    "received": unix_millis_to_json(row.received_at_ms.or_else(|| blob["received_at_ms"].as_i64())),
                },
                "expire_timer_seconds": seconds,
                "expiration_timer_update": update,
                "flags": blob["flags"],
            }),
        });
    }
    let direction = if message_type == "outgoing" {
        Direction::Outgoing
    } else {
        Direction::Incoming
    };

    let source_service_id = non_empty(row.source_service_id)
        .or_else(|| non_empty(row.legacy_source_uuid))
        .or_else(|| text_of("sourceServiceId"))
        .or_else(|| text_of("sourceUuid"));
    // The blob keeps the number as written; the column had a numeric
    // affinity before migration 1270, which drops the leading "+".
    let source_e164 = text_of("source").or(row.source_e164);
    let sender = match direction {
        Direction::Outgoing => Party {
            id: directory.me.clone(),
            display_name: directory
                .me
                .as_ref()
                .and_then(|me| directory.names.get(me).cloned()),
            is_self: true,
        },
        // The author column is set for group messages; a one-to-one
        // message without it comes from the conversation's contact.
        _ => match source_service_id.as_deref().or(conv.service_id.as_deref()) {
            Some(id) => directory.party(id),
            None => Party {
                id: source_e164.clone(),
                display_name: None,
                is_self: false,
            },
        },
    };

    // Like the other chat parsers, a message names its counterpart only:
    // the contact, or the author of a group message. The full roster of a
    // group is in its chat record.
    let participants = match direction {
        _ if conv.member_ids.is_empty() => directory.participants(conv),
        Direction::Outgoing => Vec::new(),
        _ => vec![sender.clone()],
    };

    // Table rows win; the inline list only exists on older databases.
    let attachments = if table_attachments.is_empty() {
        json_attachments(&blob)
    } else {
        table_attachments.sort_by_key(|attachment| (attachment.order, attachment.rowid));
        table_attachments
    };
    let attachments = attachments.as_slice();

    // An edit replaces the body but keeps its own state: the send state in
    // the newest entry of `editHistory`, the read status in
    // `edited_messages`. The top-level values still describe the original.
    let revision = &blob["editHistory"][0];
    let revision_sent_at = blob["editMessageTimestamp"]
        .as_i64()
        .or_else(|| revision["timestamp"].as_i64());
    let read_status = row.read_status;
    let revision_read_status = message_id
        .as_ref()
        .zip(revision_sent_at)
        .and_then(|(id, sent_at)| edits.get(&(id.clone(), sent_at)).copied())
        .or_else(|| revision["readStatus"].as_i64());
    let send_states = if revision["sendStateByConversationId"].is_object() {
        &revision["sendStateByConversationId"]
    } else {
        &blob["sendStateByConversationId"]
    };

    // `isErased` is not deletion: Signal also erases a view-once message
    // once viewed, sent or expired, and messages it cannot display.
    let is_erased = row.is_erased.or_else(|| blob["isErased"].as_bool());
    let deleted = blob
        .is_object()
        .then(|| blob["deletedForEveryone"].as_bool() == Some(true));
    let state = match direction {
        Direction::Outgoing => {
            let (delivered, read) =
                outgoing_state(send_states, directory.own_conversation.as_deref());
            MessageState {
                read,
                delivered,
                deleted,
            }
        }
        _ => MessageState {
            read: read_flag(revision_read_status.or(read_status)),
            delivered: None,
            deleted,
        },
    };

    let sent_at = row.sent_at.or_else(|| blob["sent_at"].as_i64());
    let received_at = row
        .received_at_ms
        .or_else(|| blob["received_at_ms"].as_i64());
    let body = row.body.or_else(|| text_of("body"));
    let flags = blob["flags"].as_i64();
    let is_view_once = row.is_view_once.or_else(|| blob["isViewOnce"].as_bool());
    let content_kind = content_kind(&blob, flags, is_erased, is_view_once, &body, attachments);

    // One record per file of the message, next to the inline list: the
    // indexer resolves and links attachments from these.
    let context = MessageContext {
        rowid,
        id: message_id.as_deref(),
        signal_type: &message_type,
        content_kind,
        body: body.as_deref(),
        direction,
        sender: &sender,
        conversation_id: &conversation_id,
        conversation: conv,
        sent_at,
        received_at,
    };
    let attachment_records: Vec<ObjectParsed> = attachments
        .iter()
        .filter(|attachment| attachment.is_message_file())
        .map(|attachment| attachment_record(store, attachment, &context))
        .collect();

    let message = ChatMessage {
        parser: PARSER_NAME,
        platform: PLATFORM,
        app: APP,
        conversation: Conversation {
            id: conversation_id,
            display_name: conv.name.clone(),
            participants,
        },
        direction,
        sender,
        timestamp: unix_millis_to_json(sent_at),
        sent: unix_millis_to_json(sent_at),
        received: unix_millis_to_json(received_at),
        body,
        attachments: attachments
            .iter()
            .filter(|attachment| attachment.is_message_file())
            .map(SignalAttachment::to_canonical)
            .collect(),
        state,
        source: store.source(T, message_id.as_deref(), rowid),
        details: json!({
            "message": {
                "signal_type": message_type,
                // What the row is when it is not plain text or media.
                "content_kind": content_kind,
                "flags": flags,
                "read_status": read_status,
                "revision_read_status": revision_read_status,
                "seen_status": row.seen_status,
                "source_e164": source_e164,
                "source_device": row.source_device,
                "is_erased": is_erased,
                "is_view_once": is_view_once,
                "expire_timer": row.expire_timer.or_else(|| blob["expireTimer"].as_i64()),
                "expiration_start": unix_millis_to_json(
                    row.expiration_start.or_else(|| blob["expirationStartTimestamp"].as_i64()),
                ),
                "deleted_for_everyone": blob["deletedForEveryone"].as_bool(),
                // Set on a reply to a story, which Signal shows apart
                // from the conversation.
                "story_id": row.story_id.or_else(|| text_of("storyId")),
            },
            "conversation": {
                "type": conv.conv_type,
                "group_id": conv.group_id,
            },
            // Every attachment row, including the long-message body,
            // quote, link-preview, contact and sticker ones.
            "attachments": attachments
                .iter()
                .map(SignalAttachment::to_details)
                .collect::<Vec<_>>(),
            "reactions": reactions(&blob),
            "edit_history": edit_history(&blob),
            "send_state_by_conversation_id": blob["sendStateByConversationId"].clone(),
            // Content Signal stores as structured data, verbatim.
            "quote": blob["quote"].clone(),
            "body_ranges": blob["bodyRanges"].clone(),
            "sticker": blob["sticker"].clone(),
            "poll": blob["poll"].clone(),
            "expiration_timer_update": blob["expirationTimerUpdate"].clone(),
            "contact": blob["contact"].clone(),
            "payment": blob["payment"].clone(),
            "gift_badge": blob["giftBadge"].clone(),
            "group_update": blob["group_update"].clone(),
            "errors": blob["errors"].clone(),
        }),
    };

    let mut object: ObjectParsed = message.into();
    if object.text.is_empty()
        && let Some(text) = structured_text(&blob)
    {
        object.text = text;
    }
    sink(object)?;
    attachment_records.into_iter().try_for_each(&mut *sink)
}

/// A `mobile.communication.attachment` record, in the shape the WhatsApp and
/// iMessage parsers emit: `message.rowid` and `chat.rowid` link it to its
/// message, `media` and `attachment` carry what the attachment view reads, and
/// `details` keeps everything the database records about the file, including
/// the key it is encrypted with on disk.
fn attachment_record(
    store: &Store,
    attachment: &SignalAttachment,
    message: &MessageContext,
) -> ObjectParsed {
    // A row of the table, or the message row that holds the inline entry.
    let source = match attachment.rowid {
        Some(rowid) => store.source("message_attachments", message.id, Some(rowid)),
        None => store.source("messages", message.id, message.rowid),
    };
    let conversation = message.conversation;
    let json = json!({
        "platform": PLATFORM,
        "app": APP_LABEL,
        "record_type": "attachment",
        "source": source,
        "timestamps": {
            "message": unix_millis_to_json(message.sent_at),
            "sent": unix_millis_to_json(message.sent_at),
            "received": unix_millis_to_json(message.received_at),
        },
        "direction": message.direction.as_str(),
        "message": {
            "rowid": message.rowid,
            "id": message.id,
            "text": message.body,
            "signal_type": message.signal_type,
            "content_kind": message.content_kind,
        },
        "chat": {
            "rowid": conversation.rowid,
            "id": message.conversation_id,
            "name": conversation.name,
            "type": conversation.conv_type,
            "group_id": conversation.group_id,
        },
        "sender": message.sender.to_json(),
        "media": {
            "rowid": attachment.rowid,
            "local_path": attachment.path,
            "thumbnail_local_path": attachment.thumbnail_path,
            "title": attachment.caption,
            "file_size": attachment.size,
            "width": attachment.width,
            "height": attachment.height,
            "movie_duration": attachment.duration,
        },
        "attachment": {
            "kind": attachment_kind(
                &attachment.attachment_type,
                attachment.content_type.as_deref(),
            ),
            "mime": attachment.content_type,
            "file_name": attachment.file_name,
            "local_path": attachment.path,
            // Both paths are relative to this directory of the profile.
            "local_path_base": ATTACHMENTS_DIRECTORY,
            "thumbnail_path": attachment.thumbnail_path,
            "caption": attachment.caption,
            "has_local_key": attachment.local_key.is_some(),
        },
        "details": attachment.to_details(),
    });
    ObjectParsed {
        parser: PARSER_NAME,
        kind: "mobile.communication.attachment",
        text: attachment.label(),
        json,
    }
}

/// What an `incoming` / `outgoing` row carries. Signal stores stickers, polls,
/// shared contacts, payments and a few protocol events as such rows without a
/// body, so a row with no text is not necessarily an empty message.
fn content_kind(
    blob: &Value,
    flags: Option<i64>,
    is_erased: Option<bool>,
    is_view_once: Option<bool>,
    body: &Option<String>,
    attachments: &[SignalAttachment],
) -> &'static str {
    // `DataMessage.Flags` of the Signal protocol.
    const END_SESSION: i64 = 1;
    const EXPIRATION_TIMER_UPDATE: i64 = 2;
    const PROFILE_KEY_UPDATE: i64 = 4;
    let has_flag = |flag: i64| flags.is_some_and(|flags| flags & flag != 0);
    let has_items = |key: &str| blob[key].as_array().is_some_and(|items| !items.is_empty());

    if blob["deletedForEveryone"].as_bool() == Some(true) {
        "deleted_for_everyone"
    } else if blob["sticker"].is_object() {
        "sticker"
    } else if blob["poll"].is_object() {
        "poll"
    } else if has_items("contact") {
        "contact"
    } else if blob["payment"].is_object() {
        "payment"
    } else if blob["giftBadge"].is_object() {
        "gift_badge"
    } else if blob["group_update"].is_object() {
        "group_update"
    } else if has_flag(EXPIRATION_TIMER_UPDATE) {
        "expiration_timer_update"
    } else if has_flag(END_SESSION) {
        "end_session"
    } else if has_flag(PROFILE_KEY_UPDATE) {
        "profile_key_update"
    } else if is_erased == Some(true) && is_view_once == Some(true) {
        "view_once_erased"
    } else if is_erased == Some(true) {
        "erased"
    } else if body.as_ref().is_some_and(|body| !body.is_empty()) || !attachments.is_empty() {
        "message"
    } else {
        "empty"
    }
}

/// Text to show and search for a row whose content is structured data.
fn structured_text(blob: &Value) -> Option<String> {
    let text = |value: &Value| non_empty(value.as_str().map(str::to_owned));
    text(&blob["poll"]["question"])
        .or_else(|| {
            let name = &blob["contact"][0]["name"];
            text(&name["nickname"])
                .or_else(|| join_names(text(&name["givenName"]), text(&name["familyName"])))
        })
        .or_else(|| text(&blob["sticker"]["emoji"]))
}

/// `(delivered, read)` of an outgoing message, from a per-recipient
/// `sendStateByConversationId` map.
///
/// * delivered: true once a recipient reports `Delivered`, `Read` or `Viewed`;
///   false when the recorded state holds no such confirmation, which does not
///   prove the message never arrived; unknown when no state is recorded;
/// * read: true once a recipient reports `Read` or `Viewed`, and unknown
///   otherwise, because a recipient may have disabled read receipts.
///
/// In a group this means "at least one member"; the complete map stays in
/// `details`. The owner's own entry only tracks the sync to their linked
/// devices, so it never counts for another recipient: it is read only when it
/// is the sole entry of the map (Note to Self), the rule of Signal's
/// `isMessageJustForMe`.
/// Without an identified owner, no entry can safely be classified as a
/// recipient receipt instead of linked-device synchronisation.
fn outgoing_state(states: &Value, own_conversation: Option<&str>) -> (Option<bool>, Option<bool>) {
    let Some(own_conversation) = own_conversation else {
        return (None, None);
    };
    let Some(states) = states.as_object() else {
        return (None, None);
    };
    let just_for_owner = states.len() == 1;
    let statuses: Vec<&str> = states
        .iter()
        .filter(|(conversation, _)| just_for_owner || conversation.as_str() != own_conversation)
        .filter_map(|(_, state)| state["status"].as_str())
        .collect();
    if statuses.is_empty() {
        return (None, None);
    }
    let any = |accepted: &[&str]| statuses.iter().any(|status| accepted.contains(status));
    (
        Some(any(&["Delivered", "Read", "Viewed"])),
        any(&["Read", "Viewed"]).then_some(true),
    )
}

fn reactions(blob: &Value) -> Vec<Value> {
    blob["reactions"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|reaction| reaction.is_object())
                .map(|reaction| {
                    json!({
                        "from_conversation_id": reaction["fromId"].as_str(),
                        "emoji": reaction["emoji"].as_str(),
                        "timestamp": unix_millis_to_json(reaction["timestamp"].as_i64()),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Revisions of an edited message, newest first, each with its own state.
fn edit_history(blob: &Value) -> Vec<Value> {
    blob["editHistory"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|revision| revision.is_object())
                .map(|revision| {
                    json!({
                        "body": revision["body"].as_str(),
                        "sent": unix_millis_to_json(revision["timestamp"].as_i64()),
                        "received": unix_millis_to_json(revision["received_at_ms"].as_i64()),
                        "read_status": revision["readStatus"].as_i64(),
                        "send_state_by_conversation_id":
                            revision["sendStateByConversationId"].clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
