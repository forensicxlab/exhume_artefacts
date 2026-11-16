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

use crate::core::records::{
    AppInfo, Attachment, ChatMessage, Conversation, Direction, MessageState, Party,
};
use crate::core::{
    CompanionSpec, ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserIssue,
    ParserOptionDefault, ParserOptionSpec, ParserOptionType, ParserOptionValue, ParserOptions,
    TimelineEvent,
};
use crate::formats::sqlite::sqlcipher::{SqlCipherError, SqlCipherKey, SqlCipherProfile};
use crate::formats::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, select_column, sqlite_source_json,
};
use crate::formats::timestamps::unix_millis_to_json;
use anyhow::Result;
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
            _ => return Vec::new(),
        };
        let Some(ts_unix_ms) = obj.json["timestamps"]["message"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        // `text` is the body, or the attachment name for a media-only message
        // and for an attachment record.
        let description = Some(obj.text.clone()).filter(|text| !text.is_empty());
        let actor = obj.json["sender"]["id"].as_str().map(str::to_owned);
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
        crate::run_parser_with_options(self, input, ParserOptions::default(), sink, &mut |_| Ok(()))
    }

    fn run_into_with_context(
        &self,
        input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        _diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
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

        let directory = load_directory(&conn, &schema)?;
        let attachments = load_table_attachments(&conn, &schema)?;
        let edits = load_edit_read_status(&conn, &schema)?;
        let store = Store {
            evidence: &evidence,
            cipher,
        };

        emit_conversations(&directory, &store, sink)?;
        emit_messages(
            &conn,
            &schema,
            &store,
            &directory,
            &attachments,
            &edits,
            sink,
        )
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
    Other,
}

/// SQLCipher encrypts the whole first page, so an encrypted database does not
/// start with the SQLite magic.
fn leading_bytes(path: &std::path::Path) -> Result<Leading> {
    use std::io::Read;
    const MAGIC: &[u8; 16] = b"SQLite format 3\0";
    let mut start = Vec::with_capacity(MAGIC.len());
    std::fs::File::open(path)?
        .take(MAGIC.len() as u64)
        .read_to_end(&mut start)?;
    Ok(match start.as_slice() {
        [] => Leading::Nothing,
        start if start == MAGIC => Leading::SqliteHeader,
        _ => Leading::Other,
    })
}

/// `items` row `uuid_id` carries the device owner's service id (ACI), stored
/// as `<aci>.<device id>`.
fn device_owner_service_id(conn: &SqliteConnection, schema: &SqliteSchema) -> Option<String> {
    if !schema.has_table("items") || !schema.has_column("items", "json") {
        return None;
    }
    let mut owner = None;
    // A missing or malformed row only means the owner stays unidentified.
    let _ = conn.query_rows("SELECT json FROM items WHERE id = 'uuid_id';", |row| {
        if let Some(text) = row.text(0)
            && let Ok(value) = serde_json::from_str::<Value>(&text)
            && let Some(id) = value["value"].as_str()
        {
            owner = id.split('.').next().map(str::to_owned);
        }
        Ok(())
    });
    owner.filter(|id| !id.is_empty())
}

fn load_directory(conn: &SqliteConnection, schema: &SqliteSchema) -> Result<Directory> {
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

    let me = device_owner_service_id(conn, schema);
    let mut conversations = BTreeMap::new();
    let mut names = HashMap::new();
    let mut own_conversation = None;

    conn.query_rows(&sql, |row| {
        let Some(id) = row.text(1) else {
            return Ok(());
        };
        let blob = parse_json(row.text(2));
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

/// Attachments of the current revision of every message, from the
/// `message_attachments` table (absent before migration 1360).
fn load_table_attachments(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
) -> Result<HashMap<String, Vec<SignalAttachment>>> {
    const TABLE: &str = "message_attachments";
    let mut by_message: HashMap<String, Vec<SignalAttachment>> = HashMap::new();
    if !schema.has_column(TABLE, "messageId") {
        return Ok(by_message);
    }

    let revision_filter = if schema.has_column(TABLE, "editHistoryIndex") {
        format!("WHERE a.editHistoryIndex = {ROOT_EDIT_HISTORY_INDEX}")
    } else {
        String::new()
    };
    // Interpreted columns first, then the ones reported verbatim.
    const INTERPRETED: &[&str] = &[
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
    const FIRST_VERBATIM: usize = 2 + INTERPRETED.len();
    let verbatim = ATTACHMENT_TEXT_COLUMNS
        .iter()
        .chain(ATTACHMENT_INTEGER_COLUMNS)
        .map(|(column, _)| column);
    let columns: Vec<String> = INTERPRETED
        .iter()
        .chain(verbatim)
        .enumerate()
        .map(|(index, column)| select_column(schema, TABLE, "a", column, &format!("c{index}")))
        .collect();
    let sql = format!(
        "SELECT a.messageId AS message_id, a.rowid AS row_id, {} \
         FROM {TABLE} a {revision_filter} ORDER BY a.rowid;",
        columns.join(", "),
    );

    conn.query_rows(&sql, |row| {
        let Some(message_id) = row.text(0) else {
            return Ok(());
        };
        // Most of these columns are empty on most rows; keep what is set.
        let mut recorded = Vec::new();
        let mut index = FIRST_VERBATIM as i32;
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
        by_message
            .entry(message_id)
            .or_default()
            .push(SignalAttachment {
                rowid: row.i64(1),
                attachment_type: row.text(2).unwrap_or_else(|| "attachment".to_owned()),
                order: row.i64(3),
                content_type: row.text(4),
                file_name: row.text(5),
                path: row.text(6),
                size: row.i64(7),
                local_key: row.text(8),
                plaintext_hash: row.text(9),
                caption: row.text(10),
                width: row.i64(11),
                height: row.i64(12),
                duration: row.f64(13),
                thumbnail_path: row.text(14),
                recorded,
            });
        Ok(())
    })?;

    for attachments in by_message.values_mut() {
        attachments.sort_by_key(|attachment| attachment.order);
    }
    Ok(by_message)
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

fn emit_messages(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    store: &Store,
    directory: &Directory,
    table_attachments: &HashMap<String, Vec<SignalAttachment>>,
    edits: &EditReadStatus,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    const T: &str = "messages";
    let column = |name: &str, alias: &str| select_column(schema, T, "m", name, alias);
    let sql = format!(
        "SELECT m.rowid AS row_id, m.id AS id, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, \
         {}, {}, {}, {}, {} FROM messages m ORDER BY m.rowid;",
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
    );

    conn.query_rows(&sql, |row| {
        let message_type = row.text(2).unwrap_or_default();
        if !CHAT_TYPES.contains(&message_type.as_str()) {
            return Ok(());
        }
        let rowid = row.i64(0);
        let message_id = row.text(1);
        let conversation_id = row.text(3).unwrap_or_default();
        let blob = parse_json(row.text(4));
        let text_of = |key: &str| blob[key].as_str().map(str::to_owned);

        let unknown_conversation = ConvInfo::default();
        let conv = directory
            .conversations
            .get(&conversation_id)
            .unwrap_or(&unknown_conversation);
        let direction = if message_type == "outgoing" {
            Direction::Outgoing
        } else {
            Direction::Incoming
        };

        let source_service_id = non_empty(row.text(11))
            .or_else(|| non_empty(row.text(12)))
            .or_else(|| text_of("sourceServiceId"))
            .or_else(|| text_of("sourceUuid"));
        // The blob keeps the number as written; the column had a numeric
        // affinity before migration 1270, which drops the leading "+".
        let source_e164 = text_of("source").or_else(|| row.text(13));
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
        let inline = json_attachments(&blob);
        let attachments = message_id
            .as_ref()
            .and_then(|id| table_attachments.get(id))
            .unwrap_or(&inline);

        // An edit replaces the body but keeps its own state: the send state in
        // the newest entry of `editHistory`, the read status in
        // `edited_messages`. The top-level values still describe the original.
        let revision = &blob["editHistory"][0];
        let revision_sent_at = blob["editMessageTimestamp"]
            .as_i64()
            .or_else(|| revision["timestamp"].as_i64());
        let read_status = row.i64(8);
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
        let is_erased = row.bool(10).or_else(|| blob["isErased"].as_bool());
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

        let sent_at = row.i64(6).or_else(|| blob["sent_at"].as_i64());
        let received_at = row.i64(7).or_else(|| blob["received_at_ms"].as_i64());
        let body = row.text(5).or_else(|| text_of("body"));
        let flags = blob["flags"].as_i64();
        let is_view_once = row.bool(15).or_else(|| blob["isViewOnce"].as_bool());
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
                    "seen_status": row.i64(9),
                    "source_e164": source_e164,
                    "source_device": row.i64(14),
                    "is_erased": is_erased,
                    "is_view_once": is_view_once,
                    "expire_timer": row.i64(16).or_else(|| blob["expireTimer"].as_i64()),
                    "expiration_start": unix_millis_to_json(
                        row.i64(17).or_else(|| blob["expirationStartTimestamp"].as_i64()),
                    ),
                    "deleted_for_everyone": blob["deletedForEveryone"].as_bool(),
                    // Set on a reply to a story, which Signal shows apart
                    // from the conversation.
                    "story_id": row.text(18).or_else(|| text_of("storyId")),
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
    })
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
/// is the sole entry (Note to Self).
fn outgoing_state(states: &Value, own_conversation: Option<&str>) -> (Option<bool>, Option<bool>) {
    let Some(states) = states.as_object() else {
        return (None, None);
    };
    let status_of = |state: &Value| state["status"].as_str().map(str::to_owned);
    let mut statuses: Vec<String> = states
        .iter()
        .filter(|(conversation, _)| Some(conversation.as_str()) != own_conversation)
        .filter_map(|(_, state)| status_of(state))
        .collect();
    if statuses.is_empty() {
        statuses = states.values().filter_map(status_of).collect();
    }
    if statuses.is_empty() {
        return (None, None);
    }
    let any = |accepted: &[&str]| statuses.iter().any(|s| accepted.contains(&s.as_str()));
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

fn parse_json(text: Option<String>) -> Value {
    text.and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ParserSecret;

    const ME: &str = "aaaaaaaa-0000-4000-8000-000000000001";
    const ALICE: &str = "bbbbbbbb-0000-4000-8000-000000000002";
    const BOB: &str = "cccccccc-0000-4000-8000-000000000003";
    const CAROL: &str = "dddddddd-0000-4000-8000-000000000004";
    const T0: i64 = 1_700_000_000_000;

    fn parse(sql: &str) -> Result<Vec<ObjectParsed>> {
        let tmp = tempfile::tempdir()?;
        let db = tmp.path().join("db.sqlite");
        SqliteConnection::create_for_test(&db)?.execute_batch(sql)?;
        let mut objects = Vec::new();
        SignalDesktopParser.run_into(ParserInput::Path(db), &mut |object| {
            objects.push(object);
            Ok(())
        })?;
        Ok(objects)
    }

    fn options(key: Option<&[u8]>, cipher_version: Option<i64>) -> ParserOptions {
        let mut options = ParserOptions::default();
        if let Some(key) = key {
            options
                .insert_secret(DATABASE_KEY, ParserSecret::new(key.to_vec()))
                .unwrap();
        }
        if let Some(version) = cipher_version {
            options
                .insert(CIPHER_VERSION, ParserOptionValue::Integer(version))
                .unwrap();
        }
        options
    }

    /// Run with options; the count is what reached the sink, error or not.
    fn run(input: ParserInput, options: ParserOptions) -> (Result<()>, Vec<ObjectParsed>) {
        let mut objects = Vec::new();
        let result = crate::run_parser_with_options(
            &SignalDesktopParser,
            input,
            options,
            &mut |object| {
                objects.push(object);
                Ok(())
            },
            &mut |_| Ok(()),
        );
        (result, objects)
    }

    /// What SQLCipher writes is indistinguishable from random bytes.
    fn opaque_bytes() -> Vec<u8> {
        (0..4096u32).map(|i| (i * 131 + 7) as u8).collect()
    }

    fn attachment_records(objects: &[ObjectParsed]) -> Vec<&ObjectParsed> {
        of_kind(objects, "mobile.communication.attachment")
    }

    fn of_kind<'a>(objects: &'a [ObjectParsed], kind: &str) -> Vec<&'a ObjectParsed> {
        objects
            .iter()
            .filter(|object| object.kind == kind)
            .collect()
    }

    fn messages(objects: &[ObjectParsed]) -> Vec<&ObjectParsed> {
        of_kind(objects, "mobile.communication.message")
    }

    /// The message with this Signal id.
    fn message<'a>(objects: &'a [ObjectParsed], id: &str) -> &'a serde_json::Value {
        &messages(objects)
            .into_iter()
            .find(|object| object.json["source"]["id"] == id)
            .unwrap_or_else(|| panic!("message {id} not emitted"))
            .json
    }

    /// One `messages` row; `columns` adds or overrides promoted columns.
    fn row(
        n: i64,
        kind: &str,
        conv: &str,
        body: &str,
        json: &str,
        columns: &[(&str, &str)],
    ) -> String {
        let names: String = columns
            .iter()
            .map(|(name, _)| format!(", {name}"))
            .collect();
        let values: String = columns
            .iter()
            .map(|(_, value)| format!(", {value}"))
            .collect();
        format!(
            "INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, \
             received_at_ms{names}) VALUES ({n}, 'm{n}', '{kind}', '{conv}', {body}, '{json}', \
             {sent}, {sent}{values});\n",
            sent = T0 + n * 1000,
        )
    }

    /// Current schema, with the column affinities Signal declares: promoted
    /// columns, `message_attachments` and `edited_messages` tables.
    fn current_schema() -> String {
        let alice = &format!("'{ALICE}'");
        let bob = &format!("'{BOB}'");
        let mut sql = format!(
            r#"
            CREATE TABLE items (id STRING PRIMARY KEY ASC, json TEXT);
            CREATE TABLE conversations (id STRING PRIMARY KEY ASC, json TEXT, active_at INTEGER,
                type STRING, name TEXT, profileName TEXT, profileFamilyName TEXT,
                profileFullName TEXT, e164 TEXT, serviceId TEXT, groupId TEXT);
            CREATE TABLE messages (rowid INTEGER PRIMARY KEY ASC, id STRING UNIQUE, json TEXT,
                readStatus INTEGER, sent_at INTEGER, conversationId STRING, type STRING,
                body TEXT, isErased INTEGER, isViewOnce INTEGER, sourceServiceId TEXT,
                sourceDevice INTEGER, seenStatus NUMBER default 0, received_at_ms INTEGER,
                source TEXT, expireTimer INTEGER, expirationStartTimestamp INTEGER,
                storyId STRING);
            CREATE TABLE message_attachments (messageId TEXT NOT NULL,
                editHistoryIndex INTEGER NOT NULL, attachmentType TEXT NOT NULL,
                orderInMessage INTEGER NOT NULL, size INTEGER NOT NULL,
                contentType TEXT NOT NULL, path TEXT, fileName TEXT, localKey TEXT,
                plaintextHash TEXT, caption TEXT, width INTEGER, height INTEGER,
                duration REAL, thumbnailPath TEXT, thumbnailLocalKey TEXT, digest TEXT,
                version INTEGER, transitCdnKey TEXT, transitCdnNumber INTEGER, pending INTEGER);
            CREATE TABLE edited_messages (messageId STRING, sentAt INTEGER,
                readStatus INTEGER, conversationId STRING);

            INSERT INTO items VALUES ('uuid_id', '{{"value":"{ME}.2"}}');
            INSERT INTO conversations (id, json, type, serviceId, e164, active_at) VALUES
                ('c-me', '{{"profileName":"Owner"}}', 'private', '{ME}', '+15550000001', {T0});
            INSERT INTO conversations (id, json, type, serviceId, e164, profileFullName, active_at)
                VALUES ('c-alice',
                '{{"name":"Alice Example","profileName":"Alice","profileFamilyName":"Smith"}}',
                'private', '{ALICE}', '+15550000002', 'Alice Smith', {T0} + 1000);
            INSERT INTO conversations (id, json, type, serviceId) VALUES
                ('c-bob', '{{"profileName":"Bob","profileFamilyName":"Jones"}}', 'private', '{BOB}'),
                ('c-carol', '{{"nicknameGivenName":"Caz","profileName":"Carol","username":"carol.01"}}',
                 'private', '{CAROL}');
            INSERT INTO conversations (id, json, type, groupId, active_at) VALUES ('c-team',
                '{{"name":"Team","membersV2":[{{"aci":"{ME}"}},{{"aci":"{ALICE}"}},{{"aci":"{BOB}"}}]}}',
                'group', 'Z3JvdXA=', {T0} + 9000);

            INSERT INTO message_attachments (messageId, editHistoryIndex, attachmentType,
                orderInMessage, size, contentType, path, fileName, localKey, plaintextHash,
                caption) VALUES
                ('m3', -1, 'attachment', 1, 10, 'application/pdf', 'ab/second', 'b.pdf', NULL, NULL, NULL),
                ('m3', -1, 'attachment', 0, 20, 'image/jpeg', 'ab/first', 'a.jpg', 'a2V5', 'hash', 'look'),
                ('m3', -1, 'long-message', 0, 5000, 'text/x-signal-plain', 'ab/long', NULL, NULL, NULL, NULL),
                ('m3', 0, 'attachment', 0, 20, 'image/png', 'ab/old-revision', 'old.png', NULL, NULL, NULL),
                ('m10', -1, 'sticker', 0, 300, 'image/webp', 'st/1', NULL, NULL, NULL, NULL);
            UPDATE message_attachments SET width = 640, height = 480,
                thumbnailPath = 'ab/first-thumb', thumbnailLocalKey = 'dGh1bWI=',
                digest = 'ZGlnZXN0', version = 2, transitCdnKey = 'cdn-key',
                transitCdnNumber = 3, pending = 0 WHERE path = 'ab/first';
            UPDATE message_attachments SET duration = 12.5 WHERE path = 'ab/second';
            INSERT INTO edited_messages VALUES ('m15', {T0} + 15500, 1, 'c-alice');
            "#
        );
        let read =
            |status: &'static str| [("readStatus", status), ("sourceServiceId", alice.as_str())];
        // 1-3: incoming, read / unread / viewed (ReadStatus 0 / 1 / 2).
        sql += &row(
            1,
            "incoming",
            "c-alice",
            "'hi'",
            "{}",
            &[
                ("readStatus", "0"),
                ("seenStatus", "2"),
                ("sourceServiceId", alice),
                ("source", "'+15550000002'"),
            ],
        );
        sql += &row(2, "incoming", "c-alice", "'unread one'", "{}", &read("1"));
        // 3: media only, a quote, a long-message row and an older revision.
        sql += &row(
            3,
            "incoming",
            "c-alice",
            "NULL",
            r#"{"quote":{"id":1700000001000,"text":"hi"}}"#,
            &[
                ("readStatus", "2"),
                ("sourceServiceId", alice),
                ("expireTimer", "3600"),
            ],
        );
        // 4: outgoing, delivered; the own entry is only the sync to linked devices.
        sql += &row(
            4,
            "outgoing",
            "c-alice",
            "'yo'",
            r#"{"sendStateByConversationId":{"c-alice":{"status":"Delivered"},"c-me":{"status":"Read"}},"reactions":[{"fromId":"c-alice","emoji":"👍","timestamp":1700000004500}]}"#,
            &[],
        );
        // 5-6: group, from Bob, then from the owner and viewed by Alice only.
        sql += &row(
            5,
            "incoming",
            "c-team",
            "'from bob'",
            "{}",
            &[("readStatus", "0"), ("sourceServiceId", bob)],
        );
        sql += &row(
            6,
            "outgoing",
            "c-team",
            "'welcome'",
            r#"{"sendStateByConversationId":{"c-alice":{"status":"Viewed"},"c-bob":{"status":"Pending"},"c-me":{"status":"Sent"}}}"#,
            &[],
        );
        // 7: sent, not delivered, deleted for everyone.
        sql += &row(
            7,
            "outgoing",
            "c-bob",
            "NULL",
            r#"{"sendStateByConversationId":{"c-bob":{"status":"Sent"}},"deletedForEveryone":true}"#,
            &[("isErased", "1")],
        );
        // 8: a sent view-once is erased by Signal, which is not a deletion.
        sql += &row(
            8,
            "outgoing",
            "c-bob",
            "NULL",
            r#"{"sendStateByConversationId":{"c-bob":{"status":"Delivered"}}}"#,
            &[("isErased", "1"), ("isViewOnce", "1")],
        );
        // 9: a read status outside the enum.
        sql += &row(9, "incoming", "c-alice", "'odd'", "{}", &read("99"));
        // 10-13: content stored as structured data, without a body.
        sql += &row(
            10,
            "incoming",
            "c-alice",
            "NULL",
            r#"{"sticker":{"packId":"p","stickerId":3,"emoji":"😀"}}"#,
            &read("0"),
        );
        sql += &row(
            11,
            "incoming",
            "c-alice",
            "NULL",
            r#"{"poll":{"question":"Where do we meet?","options":["Park","Cafe"],"allowMultiple":false}}"#,
            &read("0"),
        );
        sql += &row(
            12,
            "outgoing",
            "c-alice",
            "NULL",
            r#"{"flags":2,"expirationTimerUpdate":{"expireTimer":3600}}"#,
            &[],
        );
        sql += &row(
            13,
            "incoming",
            "c-alice",
            "NULL",
            r#"{"contact":[{"name":{"givenName":"Dana","familyName":"Lee"},"number":[{"value":"+15550000009"}]}]}"#,
            &read("0"),
        );
        // 14: edited from another device: the top-level state is the original's.
        sql += &row(
            14,
            "outgoing",
            "c-alice",
            "'meet at 6'",
            r#"{"sendStateByConversationId":{"c-alice":{"status":"Read"}},"editMessageTimestamp":1700000014500,"editHistory":[{"body":"meet at 6","timestamp":1700000014500,"sendStateByConversationId":{"c-alice":{"status":"Sent"}}},{"body":"meet at 5","timestamp":1700000014000,"sendStateByConversationId":{"c-alice":{"status":"Read"}}}]}"#,
            &[],
        );
        // 15: an edit received after the original was read, itself still unread.
        sql += &row(
            15,
            "incoming",
            "c-alice",
            "'new text'",
            r#"{"editMessageTimestamp":1700000015500,"editHistory":[{"body":"new text","timestamp":1700000015500,"readStatus":1},{"body":"old text","timestamp":1700000015000,"readStatus":0}]}"#,
            &read("0"),
        );
        // 16: a reply to a story; 17: Note to Self, where only the own entry exists.
        sql += &row(
            16,
            "incoming",
            "c-team",
            "'nice story'",
            "{}",
            &[
                ("readStatus", "0"),
                ("sourceServiceId", bob),
                ("storyId", "'story-1'"),
            ],
        );
        sql += &row(
            17,
            "outgoing",
            "c-me",
            "'note'",
            r#"{"sendStateByConversationId":{"c-me":{"status":"Read"}}}"#,
            &[],
        );
        // System rows are not chat messages.
        sql += &row(18, "group-v2-change", "c-team", "NULL", "{}", &[]);
        sql += &row(19, "call-history", "c-alice", "NULL", "{}", &[]);
        sql
    }

    #[test]
    fn parses_current_schema() -> Result<()> {
        let objects = parse(&current_schema())?;
        let chats = of_kind(&objects, "mobile.communication.chat");
        assert_eq!(chats.len(), 5);
        // Rows 18 and 19 are system rows.
        assert_eq!(messages(&objects).len(), 17);

        // Conversations: stable order, convention shape, provenance.
        let ids: Vec<_> = chats.iter().map(|c| c.json["chat"]["id"].clone()).collect();
        assert_eq!(ids, ["c-alice", "c-bob", "c-carol", "c-me", "c-team"]);
        let alice = &chats[0].json;
        assert_eq!(alice["app"], "signal");
        assert_eq!(alice["record_type"], "chat");
        assert_eq!(alice["source"]["rowid"], 2);
        assert_eq!(alice["timestamps"]["last_active"]["unix_ms"], T0 + 1000);
        // The address-book name is the title; the profile name is kept whole.
        assert_eq!(alice["chat"]["name"], "Alice Example");
        assert_eq!(alice["chat"]["profile_name"], "Alice Smith");
        // Without a `profileFullName` column value the parts are joined.
        assert_eq!(chats[1].json["chat"]["name"], "Bob Jones");
        // A nickname wins, as in Signal, and nothing else is lost.
        assert_eq!(chats[2].json["chat"]["name"], "Caz");
        assert_eq!(chats[2].json["chat"]["profile_name"], "Carol");
        assert_eq!(chats[2].json["chat"]["username"], "carol.01");
        assert_eq!(chats[3].json["chat"]["is_self"], true);
        let team = &chats[4].json["chat"];
        assert_eq!(team["group_id"], "Z3JvdXA=");
        assert_eq!(team["participants"].as_array().unwrap().len(), 3);
        assert_eq!(team["participants"][0]["is_self"], true);
        assert_eq!(team["participants"][2]["display_name"], "Bob Jones");

        // m1: incoming and read; the owner id drops its device suffix.
        let m1 = message(&objects, "m1");
        assert_eq!(m1["schema"], "chat.v1");
        assert_eq!(m1["platform"], "desktop");
        assert_eq!(m1["direction"], "incoming");
        assert_eq!(m1["body"], "hi");
        assert_eq!(m1["conversation"]["display_name"], "Alice Example");
        assert_eq!(m1["conversation"]["participants"][0]["id"], ALICE);
        assert_eq!(m1["sender"]["id"], ALICE);
        assert_eq!(m1["sender"]["display_name"], "Alice Example");
        assert_eq!(m1["state"]["read"], true);
        assert!(m1["state"]["delivered"].is_null());
        assert_eq!(m1["state"]["deleted"], false);
        assert_eq!(m1["timestamps"]["message"]["unix_ms"], T0 + 1000);
        assert_eq!(m1["source"]["rowid"], 1);
        assert_eq!(m1["details"]["message"]["source_e164"], "+15550000002");
        assert_eq!(m1["details"]["message"]["content_kind"], "message");

        // ReadStatus is Read = 0, Unread = 1, Viewed = 2; anything else is unknown.
        assert_eq!(message(&objects, "m2")["state"]["read"], false);
        let m3 = message(&objects, "m3");
        assert_eq!(m3["state"]["read"], true);
        assert_eq!(m3["details"]["message"]["read_status"], 2);
        assert_eq!(m3["details"]["message"]["expire_timer"], 3600);
        assert_eq!(m3["details"]["quote"]["text"], "hi");
        assert!(message(&objects, "m9")["state"]["read"].is_null());
        assert_eq!(
            message(&objects, "m9")["details"]["message"]["read_status"],
            99
        );

        // m3 attachments: from the table, ordered, current revision only; the
        // long-message row is kept in details but is not a user attachment.
        let attachments = m3["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 2);
        assert_eq!(attachments[0]["filename"], "a.jpg");
        assert_eq!(attachments[0]["kind"], "image");
        assert_eq!(attachments[0]["mime"], "image/jpeg");
        assert_eq!(attachments[0]["local_path"], "ab/first");
        assert_eq!(attachments[0]["size_bytes"], 20);
        assert_eq!(attachments[1]["kind"], "document");
        let detailed = m3["details"]["attachments"].as_array().unwrap();
        assert_eq!(detailed.len(), 3);
        assert_eq!(detailed[0]["local_key"], "a2V5");
        assert_eq!(detailed[0]["caption"], "look");
        assert!(
            detailed
                .iter()
                .any(|a| a["attachment_type"] == "long-message")
        );

        // m4: delivered to its recipient. Read is unknown, not false: the
        // recipient may have read receipts off. The own entry is ignored.
        let m4 = message(&objects, "m4");
        assert_eq!(m4["direction"], "outgoing");
        assert_eq!(m4["sender"]["is_self"], true);
        assert_eq!(m4["sender"]["id"], ME);
        assert_eq!(m4["sender"]["display_name"], "Owner");
        assert_eq!(m4["state"]["delivered"], true);
        assert!(m4["state"]["read"].is_null());
        assert_eq!(m4["details"]["reactions"][0]["emoji"], "👍");
        assert_eq!(
            m4["details"]["reactions"][0]["timestamp"]["unix_ms"],
            T0 + 4500
        );

        // m5: a group message is attributed to its author, not to the group.
        let m5 = message(&objects, "m5");
        assert_eq!(m5["conversation"]["display_name"], "Team");
        assert_eq!(
            m5["conversation"]["participants"].as_array().unwrap().len(),
            1
        );
        assert_eq!(m5["sender"]["id"], BOB);
        assert_eq!(m5["sender"]["display_name"], "Bob Jones");
        assert_eq!(m5["details"]["conversation"]["type"], "group");

        // m6: one member viewed it; the per-member picture stays in details.
        let m6 = message(&objects, "m6");
        assert_eq!(m6["state"]["delivered"], true);
        assert_eq!(m6["state"]["read"], true);
        assert_eq!(
            m6["details"]["send_state_by_conversation_id"]["c-bob"]["status"],
            "Pending"
        );

        // m7 was deleted for everyone; m8 was only erased by Signal because it
        // is a sent view-once, and must not be reported as deleted.
        let m7 = message(&objects, "m7");
        assert_eq!(m7["state"]["delivered"], false);
        assert!(m7["state"]["read"].is_null());
        assert_eq!(m7["state"]["deleted"], true);
        assert_eq!(
            m7["details"]["message"]["content_kind"],
            "deleted_for_everyone"
        );
        let m8 = message(&objects, "m8");
        assert_eq!(m8["state"]["deleted"], false);
        assert_eq!(m8["state"]["delivered"], true);
        assert_eq!(m8["details"]["message"]["is_erased"], true);
        assert_eq!(m8["details"]["message"]["content_kind"], "view_once_erased");

        // Structured content is identified, kept verbatim and searchable.
        let m10 = message(&objects, "m10");
        assert_eq!(m10["details"]["message"]["content_kind"], "sticker");
        assert_eq!(m10["attachments"][0]["kind"], "sticker");
        assert_eq!(m10["has_attachments"], true);
        assert_eq!(m10["details"]["sticker"]["emoji"], "😀");
        let m11 = message(&objects, "m11");
        assert!(m11["body"].is_null());
        assert_eq!(m11["details"]["message"]["content_kind"], "poll");
        assert_eq!(m11["details"]["poll"]["options"][1], "Cafe");
        let text_of = |id: &str| {
            messages(&objects)
                .into_iter()
                .find(|object| object.json["source"]["id"] == id)
                .map(|object| object.text.clone())
        };
        assert_eq!(text_of("m3").as_deref(), Some("a.jpg"));
        assert_eq!(text_of("m10").as_deref(), Some("[sticker]"));
        assert_eq!(text_of("m11").as_deref(), Some("Where do we meet?"));
        assert_eq!(text_of("m13").as_deref(), Some("Dana Lee"));
        let m12 = &message(&objects, "m12")["details"]["message"];
        assert_eq!(m12["content_kind"], "expiration_timer_update");
        assert_eq!(m12["flags"], 2);
        assert_eq!(
            message(&objects, "m13")["details"]["message"]["content_kind"],
            "contact"
        );

        // m14: the body is the edit, so the state is the edit's, not the
        // original's "Read"; both revisions keep their own state in details.
        let m14 = message(&objects, "m14");
        assert_eq!(m14["body"], "meet at 6");
        assert_eq!(m14["state"]["delivered"], false);
        assert!(m14["state"]["read"].is_null());
        let history = &m14["details"]["edit_history"];
        assert_eq!(history.as_array().unwrap().len(), 2);
        assert_eq!(history[1]["body"], "meet at 5");
        assert_eq!(
            history[1]["send_state_by_conversation_id"]["c-alice"]["status"],
            "Read"
        );
        // m15: the original was read, the edit is not (`edited_messages`).
        let m15 = message(&objects, "m15");
        assert_eq!(m15["state"]["read"], false);
        assert_eq!(m15["details"]["message"]["read_status"], 0);
        assert_eq!(m15["details"]["message"]["revision_read_status"], 1);

        assert_eq!(
            message(&objects, "m16")["details"]["message"]["story_id"],
            "story-1"
        );
        // m17, Note to Self: the own entry is the only one, so it counts.
        let m17 = message(&objects, "m17");
        assert_eq!(m17["state"]["delivered"], true);
        assert_eq!(m17["state"]["read"], true);

        // Each file of a message is also a record of its own, right after the
        // message: two for m3 (not the long-message row, not the old
        // revision), one for the sticker of m10.
        let records = attachment_records(&objects);
        assert_eq!(records.len(), 3);
        let m3_at = objects
            .iter()
            .position(|object| object.json["source"]["id"] == "m3")
            .unwrap();
        assert_eq!(objects[m3_at].kind, "mobile.communication.message");
        assert_eq!(objects[m3_at + 1].kind, "mobile.communication.attachment");
        assert_eq!(objects[m3_at + 2].kind, "mobile.communication.attachment");
        let first = &objects[m3_at + 1];
        assert_eq!(first.text, "a.jpg");
        assert_eq!(first.json["record_type"], "attachment");
        assert_eq!(first.json["platform"], "desktop");
        assert_eq!(first.json["app"], "signal");
        assert_eq!(first.json["direction"], "incoming");
        // The links the indexer follows.
        assert_eq!(first.json["message"]["rowid"], 3);
        assert_eq!(first.json["message"]["id"], "m3");
        let alice_chat = chats
            .iter()
            .find(|chat| chat.json["chat"]["id"] == "c-alice")
            .unwrap();
        assert!(first.json["chat"]["rowid"].is_i64());
        assert_eq!(
            first.json["chat"]["rowid"],
            alice_chat.json["source"]["rowid"]
        );
        assert_eq!(first.json["chat"]["id"], "c-alice");
        assert_eq!(first.json["sender"]["id"], ALICE);
        assert_eq!(first.json["timestamps"]["message"]["unix_ms"], T0 + 3000);
        assert_eq!(first.json["source"]["table"], "message_attachments");
        assert_eq!(first.json["source"]["id"], "m3");
        assert!(first.json["media"]["rowid"].is_i64());
        assert_eq!(first.json["source"]["rowid"], first.json["media"]["rowid"]);
        // What the attachment view reads.
        assert_eq!(first.json["attachment"]["kind"], "image");
        assert_eq!(first.json["attachment"]["mime"], "image/jpeg");
        assert_eq!(first.json["attachment"]["file_name"], "a.jpg");
        assert_eq!(first.json["attachment"]["local_path"], "ab/first");
        assert_eq!(
            first.json["attachment"]["local_path_base"],
            "attachments.noindex"
        );
        assert_eq!(first.json["attachment"]["caption"], "look");
        assert_eq!(first.json["attachment"]["has_local_key"], true);
        assert_eq!(first.json["media"]["local_path"], "ab/first");
        assert_eq!(
            first.json["media"]["thumbnail_local_path"],
            "ab/first-thumb"
        );
        assert_eq!(first.json["media"]["file_size"], 20);
        assert_eq!(first.json["media"]["width"], 640);
        assert_eq!(first.json["media"]["height"], 480);
        // The path, the key and the other columns stay as recorded.
        let recorded = &first.json["details"];
        assert_eq!(recorded["path"], "ab/first");
        assert_eq!(recorded["local_key"], "a2V5");
        assert_eq!(recorded["plaintext_hash"], "hash");
        assert_eq!(recorded["thumbnail_local_key"], "dGh1bWI=");
        assert_eq!(recorded["digest"], "ZGlnZXN0");
        assert_eq!(recorded["version"], 2);
        assert_eq!(recorded["transit_cdn_key"], "cdn-key");
        assert_eq!(recorded["transit_cdn_number"], 3);
        assert_eq!(recorded["pending"], 0);
        // A column that holds nothing is not reported as a value.
        assert!(recorded.get("screenshot_path").is_none());
        // The same detail is in the message.
        assert_eq!(m3["details"]["attachments"][0], *recorded);
        let second = &objects[m3_at + 2];
        assert_eq!(second.text, "b.pdf");
        assert_eq!(second.json["attachment"]["kind"], "document");
        assert_eq!(second.json["attachment"]["has_local_key"], false);
        assert_eq!(second.json["media"]["movie_duration"], 12.5);
        let sticker = records[2];
        assert_eq!(sticker.json["message"]["id"], "m10");
        assert_eq!(sticker.json["attachment"]["kind"], "sticker");
        assert_eq!(sticker.json["message"]["content_kind"], "sticker");
        // An attachment record is a timeline event too.
        let events = SignalDesktopParser.extract_timeline_events(first);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "mobile.communication.attachment");
        assert_eq!(events[0].ts_unix_ms, T0 + 3000);
        assert_eq!(events[0].description.as_deref(), Some("a.jpg"));
        assert_eq!(events[0].actor.as_deref(), Some(ALICE));
        // A decrypted database is not reported as opened with a key.
        assert!(m3["source"]["cipher_profile"].is_null());

        // One timeline event per message, described by its display text.
        let media_only = messages(&objects)[2];
        let events = SignalDesktopParser.extract_timeline_events(media_only);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ts_unix_ms, T0 + 3000);
        assert_eq!(events[0].description.as_deref(), Some("a.jpg"));
        assert_eq!(events[0].actor.as_deref(), Some(ALICE));
        assert!(
            SignalDesktopParser
                .extract_timeline_events(chats[0])
                .is_empty()
        );
        Ok(())
    }

    /// Older schema: `uuid` / `sourceUuid` columns, a numeric-affinity
    /// `source`, inline attachments and stickers, plain member lists, and no
    /// `items` table.
    #[test]
    fn parses_legacy_schema() -> Result<()> {
        let objects = parse(&format!(
            r#"
            CREATE TABLE conversations (id STRING PRIMARY KEY ASC, json TEXT, type STRING,
                uuid TEXT, e164 TEXT);
            CREATE TABLE messages (id STRING PRIMARY KEY ASC, type STRING, conversationId STRING,
                json TEXT, body TEXT, sent_at INTEGER, sourceUuid TEXT, source STRING);
            INSERT INTO conversations VALUES ('c1', '{{}}', 'private', '{ALICE}', '+15550000002');
            INSERT INTO conversations VALUES ('g1',
                '{{"name":"Old group","members":["{ALICE}","{BOB}"]}}', 'group', NULL, NULL);
            INSERT INTO messages VALUES ('m1','incoming','g1',
                '{{"source":"+15550000002","received_at_ms":1600000000500,"attachments":[7,null,{{"path":"cd/x","fileName":"clip.mp4","contentType":"video/mp4","size":7}}]}}',
                'old', 1600000000000, '{ALICE}', '+15550000002');
            INSERT INTO messages VALUES ('m2','outgoing','c1','{{"body":"json body"}}',
                NULL, 1600000001000, NULL, NULL);
            INSERT INTO messages VALUES ('m3','incoming','c1','not json',
                'damaged', 1600000002000, '{ALICE}', NULL);
            INSERT INTO messages VALUES ('m4','incoming','c1',
                '{{"sticker":{{"packId":"p","data":{{"path":"st/1","contentType":"image/webp","size":9}}}}}}',
                NULL, 1600000003000, '{ALICE}', NULL);
            "#
        ))?;
        assert_eq!(messages(&objects).len(), 4);

        let m1 = message(&objects, "m1");
        assert_eq!(m1["sender"]["id"], ALICE);
        // No contact name stored: the phone number stands in.
        assert_eq!(m1["sender"]["display_name"], "+15550000002");
        // The numeric column lost the "+"; the blob has the number as written.
        assert_eq!(m1["details"]["message"]["source_e164"], "+15550000002");
        // A group message names its author; the roster is in the chat record.
        assert_eq!(
            m1["conversation"]["participants"].as_array().unwrap().len(),
            1
        );
        let group = of_kind(&objects, "mobile.communication.chat")
            .into_iter()
            .find(|object| object.json["chat"]["id"] == "g1")
            .unwrap();
        assert_eq!(
            group.json["chat"]["participants"].as_array().unwrap().len(),
            2
        );
        // Only real attachment entries count, not stray values in the list.
        assert_eq!(m1["attachments"].as_array().unwrap().len(), 1);
        assert_eq!(m1["attachments"][0]["kind"], "video");
        assert_eq!(m1["attachments"][0]["filename"], "clip.mp4");
        assert_eq!(
            m1["timestamps"]["received"]["unix_ms"],
            1_600_000_000_500i64
        );
        // Columns this version lacks stay null instead of being invented.
        assert!(m1["state"]["read"].is_null());
        assert_eq!(m1["state"]["deleted"], false);

        let m2 = message(&objects, "m2");
        assert_eq!(m2["body"], "json body");
        assert_eq!(m2["sender"]["is_self"], true);
        assert!(m2["sender"]["id"].is_null());
        assert!(m2["state"]["delivered"].is_null());
        assert!(m2["state"]["read"].is_null());

        // An unreadable blob says nothing about deletion.
        let m3 = message(&objects, "m3");
        assert_eq!(m3["body"], "damaged");
        assert!(m3["state"]["deleted"].is_null());

        let m4 = message(&objects, "m4");
        assert_eq!(m4["attachments"][0]["kind"], "sticker");
        assert_eq!(m4["attachments"][0]["local_path"], "st/1");

        // Inline attachments have no row of their own: the record points at
        // the message row and keeps the entry of the message json.
        let records = attachment_records(&objects);
        assert_eq!(records.len(), 2);
        let clip = &records[0].json;
        assert_eq!(clip["message"]["id"], "m1");
        assert_eq!(clip["attachment"]["kind"], "video");
        assert_eq!(clip["attachment"]["local_path"], "cd/x");
        assert!(clip["media"]["rowid"].is_null());
        assert_eq!(clip["source"]["table"], "messages");
        assert_eq!(clip["source"]["rowid"], clip["message"]["rowid"]);
        assert_eq!(clip["details"]["inline_json"]["fileName"], "clip.mp4");
        assert_eq!(records[1].json["attachment"]["kind"], "sticker");
        assert_eq!(m4["details"]["message"]["content_kind"], "sticker");
        Ok(())
    }

    /// Damaged or hostile content must never panic nor hide the rows around
    /// it: every row of a chat type is still emitted.
    #[test]
    fn survives_hostile_content() -> Result<()> {
        let deep = format!("{}{}", "[".repeat(3000), "]".repeat(3000));
        let blobs = [
            "".to_owned(),
            "null".to_owned(),
            "[]".to_owned(),
            "42".to_owned(),
            "{".to_owned(),
            "not json".to_owned(),
            deep.clone(),
            r#"{"attachments":"x","reactions":{"a":1},"editHistory":[1,null,"x"]}"#.to_owned(),
            r#"{"attachments":[null,7,{"size":"big","path":3}],"reactions":[null,{"timestamp":"soon"}]}"#.to_owned(),
            r#"{"sendStateByConversationId":[1,2],"deletedForEveryone":"yes"}"#.to_owned(),
            r#"{"sendStateByConversationId":{"c":null,"d":{"status":5},"e":{}}}"#.to_owned(),
            format!(r#"{{"body":{{"nested":1}},"sent_at":"x","received_at_ms":1e400,"quote":{deep}}}"#),
        ];
        let mut sql = String::from(
            r#"
            CREATE TABLE items (id TEXT PRIMARY KEY, json TEXT);
            CREATE TABLE conversations (id, json, type, serviceId, e164, groupId, active_at);
            CREATE TABLE messages (id, type, conversationId, json, body, sent_at,
                received_at_ms, readStatus, seenStatus, isErased, isViewOnce,
                sourceServiceId, source, sourceDevice, expireTimer, expirationStartTimestamp);
            CREATE TABLE message_attachments (messageId, editHistoryIndex, attachmentType,
                orderInMessage, size, contentType, path, fileName, localKey);
            INSERT INTO items VALUES ('uuid_id', '{"value":17}');
            INSERT INTO conversations VALUES (NULL, '{', 3, 4, 1.5, x'00', 'soon');
            INSERT INTO conversations VALUES ('c', '{"membersV2":"all","members":[{"aci":7},[],null,3],"name":["a"]}',
                'group', x'ff', NULL, NULL, -9223372036854775808);
            INSERT INTO conversations VALUES ('c', '[]', NULL, '', '', '', 9223372036854775807);
            INSERT INTO message_attachments VALUES ('m0', -1, '', -2, -5, '', '../../etc', NULL, NULL);
            INSERT INTO message_attachments VALUES ('m1', -1, NULL, NULL, 'big', x'00', 7, x'fffe', 9);
            INSERT INTO message_attachments VALUES (NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            "#,
        );
        let numbers = [
            "NULL",
            "-1",
            "9223372036854775807",
            "1e300",
            "'text'",
            "x'fffe'",
        ];
        for (index, blob) in blobs.iter().enumerate() {
            let number = numbers[index % numbers.len()];
            let kind = if index % 2 == 0 {
                "incoming"
            } else {
                "outgoing"
            };
            sql.push_str(&format!(
                "INSERT INTO messages VALUES ('m{index}', '{kind}', {conv}, '{blob}', {body}, \
                 {number}, {number}, {number}, {number}, {number}, {number}, {source}, 5, \
                 {number}, {number}, {number});\n",
                conv = ["NULL", "'c'", "'missing'", "5"][index % 4],
                body = ["NULL", "''", "x'fffe'", "7"][index % 4],
                source = ["NULL", "''", "x'ff'", "9"][index % 4],
            ));
        }
        // Rows that are not chat messages, including look-alike types.
        sql.push_str(
            "INSERT INTO messages (id, type) VALUES ('s1', NULL), ('s2', ''), ('s3', 'INCOMING'), \
             ('s4', 7), (NULL, 'incoming');",
        );

        let objects = parse(&sql)?;
        // One per row of type incoming/outgoing: the twelve above and the
        // row without an id.
        assert_eq!(messages(&objects).len(), blobs.len() + 1);
        // An unreadable owner id is not turned into an identity.
        assert!(
            messages(&objects)
                .iter()
                .all(|message| message.json["sender"]["id"] != 17)
        );
        Ok(())
    }

    #[test]
    fn declares_the_shared_sqlcipher_options() {
        ParserContext::validate_specs(SignalDesktopParser.option_specs()).unwrap();
        let [key, version] = SignalDesktopParser.option_specs() else {
            panic!("two options expected");
        };
        assert_eq!(key.name, "database_key");
        assert_eq!(key.value_type, ParserOptionType::Secret);
        assert!(!key.required);
        assert_eq!(version.name, "cipher_version");
        assert!(matches!(
            version.default,
            Some(ParserOptionDefault::Integer(4))
        ));
    }

    #[test]
    fn rejects_an_unknown_cipher_version_before_reading() {
        let (result, objects) = run(ParserInput::Bytes(opaque_bytes()), options(None, Some(5)));
        let error = result.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ParserInputError>(),
            Some(ParserInputError::InvalidConfiguration { option, .. }) if option == "cipher_version"
        ));
        assert!(objects.is_empty());
    }

    #[test]
    fn rejects_an_empty_file_without_asking_for_a_key() {
        let (result, objects) = run(ParserInput::Bytes(Vec::new()), options(None, None));
        let error = result.unwrap_err();
        assert!(error.downcast_ref::<ParserInputError>().is_none());
        assert!(error.to_string().ends_with("is empty"));
        assert!(objects.is_empty());
    }

    /// A build without the backend says so at once: a key would not help.
    #[cfg(not(feature = "sqlcipher"))]
    #[test]
    fn reports_a_missing_sqlcipher_backend() {
        for options in [options(None, None), options(Some(&[b'0'; 64]), None)] {
            let (result, objects) = run(ParserInput::Bytes(opaque_bytes()), options);
            let error = result.unwrap_err();
            assert_eq!(error.downcast_ref(), Some(&SqlCipherError::Unavailable));
            assert!(error.downcast_ref::<ParserInputError>().is_none());
            assert!(format!("{error:#}").contains("probably still encrypted"));
            assert!(objects.is_empty());
        }
    }

    #[cfg(feature = "sqlcipher")]
    mod encrypted {
        use super::*;
        use crate::core::ParserInputReason;
        use std::path::{Path, PathBuf};

        const KEY: &[u8; 64] = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        const OTHER_KEY: &[u8; 64] =
            b"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

        /// The current schema, keyed the way Signal Desktop keys its database:
        /// `PRAGMA key = "x'<64 hex>'"`, through the documented SQL interface.
        fn encrypted_db(directory: &Path, compatibility: u8) -> Result<PathBuf> {
            let db = directory.join("db.sqlite");
            let conn = SqliteConnection::create_for_test(&db)?;
            conn.execute_batch(&format!(
                "PRAGMA key = \"x'{}'\"; PRAGMA cipher_compatibility = {compatibility};",
                std::str::from_utf8(KEY)?
            ))?;
            conn.execute_batch(&current_schema())?;
            drop(conn);
            let bytes = std::fs::read(&db)?;
            assert!(!bytes.starts_with(b"SQLite format 3"));
            assert!(!bytes.windows(10).any(|window| window == b"unread one"));
            Ok(db)
        }

        /// Everything but `source`, which names the file and how it was opened.
        fn content(objects: &[ObjectParsed]) -> Vec<(&'static str, String, Value)> {
            objects
                .iter()
                .map(|object| {
                    let mut json = object.json.clone();
                    json.as_object_mut().unwrap().remove("source");
                    (object.kind, object.text.clone(), json)
                })
                .collect()
        }

        #[test]
        fn asks_for_the_key_before_emitting_anything() -> Result<()> {
            let tmp = tempfile::tempdir()?;
            let db = encrypted_db(tmp.path(), 4)?;
            for input in [ParserInput::Path(db), ParserInput::Bytes(opaque_bytes())] {
                let (result, objects) = run(input, options(None, None));
                let error = result.unwrap_err();
                let Some(ParserInputError::NeedsInput { requests }) = error.downcast_ref() else {
                    panic!("expected a request for input, got {error:#}");
                };
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].name, "database_key");
                assert_eq!(requests[0].value_type, ParserOptionType::Secret);
                assert_eq!(requests[0].reason, ParserInputReason::Missing);
                assert!(objects.is_empty());
            }
            Ok(())
        }

        #[test]
        fn reads_an_encrypted_database_like_its_decrypted_copy() -> Result<()> {
            let tmp = tempfile::tempdir()?;
            let db = encrypted_db(tmp.path(), 4)?;
            let before = std::fs::read(&db)?;
            let (result, objects) = run(ParserInput::Path(db.clone()), options(Some(KEY), None));
            result?;
            let plain = parse(&current_schema())?;
            assert_eq!(content(&objects), content(&plain));
            assert_eq!(messages(&objects).len(), 17);
            assert_eq!(attachment_records(&objects).len(), 3);
            // Every record says how its database was opened.
            assert!(
                objects
                    .iter()
                    .all(|object| object.json["source"]["cipher_profile"] == "4")
            );
            // The evidence is read from a working copy.
            assert_eq!(std::fs::read(&db)?, before);
            Ok(())
        }

        #[test]
        fn opens_a_sqlcipher_3_database_when_told_so() -> Result<()> {
            let tmp = tempfile::tempdir()?;
            let db = encrypted_db(tmp.path(), 3)?;
            let (result, objects) = run(ParserInput::Path(db.clone()), options(Some(KEY), None));
            assert_eq!(
                result.unwrap_err().downcast_ref(),
                Some(&SqlCipherError::UnreadableDatabase)
            );
            assert!(objects.is_empty());
            let (result, objects) = run(ParserInput::Path(db), options(Some(KEY), Some(3)));
            result?;
            assert_eq!(messages(&objects).len(), 17);
            assert_eq!(objects[0].json["source"]["cipher_profile"], "3");
            Ok(())
        }

        /// A failed open does not single out the key: the cipher settings or
        /// the evidence may be responsible, so no "rejected" request is made.
        #[test]
        fn keeps_a_failed_open_undetermined() -> Result<()> {
            let tmp = tempfile::tempdir()?;
            let db = encrypted_db(tmp.path(), 4)?;
            let mut damaged = std::fs::read(&db)?;
            damaged[100..600].fill(0x5a);
            for (input, key) in [
                (ParserInput::Path(db), OTHER_KEY),
                (ParserInput::Bytes(damaged), KEY),
                (ParserInput::Bytes(opaque_bytes()), KEY),
            ] {
                let (result, objects) = run(input, options(Some(key), None));
                let error = result.unwrap_err();
                assert_eq!(
                    error.downcast_ref(),
                    Some(&SqlCipherError::UnreadableDatabase)
                );
                assert!(error.downcast_ref::<ParserInputError>().is_none());
                let shown = format!("{error:#}");
                assert!(shown.contains("key or cipher profile may be incorrect"));
                assert!(!shown.contains(std::str::from_utf8(key)?));
                assert!(objects.is_empty());
            }
            Ok(())
        }

        #[test]
        fn refuses_a_malformed_key_without_echoing_it() -> Result<()> {
            let tmp = tempfile::tempdir()?;
            let db = encrypted_db(tmp.path(), 4)?;
            let malformed = b"correct horse battery staple";
            let (result, objects) = run(ParserInput::Path(db), options(Some(malformed), None));
            let error = result.unwrap_err();
            let Some(ParserInputError::InvalidConfiguration { option, message }) =
                error.downcast_ref()
            else {
                panic!("expected an invalid option, got {error:#}");
            };
            assert_eq!(option, "database_key");
            assert!(message.contains("64 hexadecimal characters"));
            assert!(!format!("{error:#}").contains("horse"));
            assert!(objects.is_empty());
            Ok(())
        }

        #[test]
        fn ignores_the_key_for_a_decrypted_database() -> Result<()> {
            let tmp = tempfile::tempdir()?;
            let db = tmp.path().join("db.sqlite");
            SqliteConnection::create_for_test(&db)?.execute_batch(&current_schema())?;
            let (result, objects) = run(ParserInput::Path(db), options(Some(KEY), None));
            result?;
            assert_eq!(messages(&objects).len(), 17);
            assert!(objects[0].json["source"]["cipher_profile"].is_null());
            Ok(())
        }
    }

    #[test]
    fn rejects_a_database_that_is_not_signal() {
        let error = parse("CREATE TABLE unrelated (id INTEGER);").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing table(s) conversations, messages")
        );
        // Same table names, another application's columns.
        let error = parse(
            "CREATE TABLE conversations (id, title); CREATE TABLE messages (id, text);
             INSERT INTO conversations VALUES (1, 'x');",
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "not a Signal Desktop database: missing column(s) conversations.json"
        );
    }
}
