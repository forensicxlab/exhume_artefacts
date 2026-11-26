use super::*;
use crate::core::ParserSecret;

const ME: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const ALICE: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const BOB: &str = "cccccccc-0000-4000-8000-000000000003";
const CAROL: &str = "dddddddd-0000-4000-8000-000000000004";
const T0: i64 = 1_700_000_000_000;

#[test]
fn cached_conversation_previews_survive_without_becoming_reconstructed_messages() -> Result<()> {
    let records = parse(&format!(
        r#"{}
        UPDATE conversations SET json = json_set(json,
            '$.lastMessage', 'SYNTHETIC expired preview',
            '$.lastMessageStatus', 'read', '$.lastMessageAuthor', 'You',
            '$.lastMessageReceivedAt', 47, '$.lastMessageReceivedAtMs', {T0})
            WHERE id = 'c-alice';
    "#,
        current_schema()
    ))?;
    let chat = records
        .iter()
        .find(|r| r.kind == "mobile.communication.chat" && r.json["chat"]["id"] == "c-alice")
        .unwrap();
    let cache = &chat.json["chat"]["last_message_cache"];
    assert_eq!(cache["text"], "SYNTHETIC expired preview");
    assert_eq!(cache["status"], "read");
    assert_eq!(cache["received_at_counter"], 47);
    assert_eq!(cache["received_at"]["unix_ms"], T0);
    assert!(
        !messages(&records)
            .iter()
            .any(|r| r.json["body"] == "SYNTHETIC expired preview")
    );
    assert!(chat.json["source"]["rowid"].is_number());
    Ok(())
}

#[test]
fn native_timer_notifications_preserve_settings_without_inventing_message_receipts() -> Result<()> {
    let sql = format!(
        r#"{}
        UPDATE conversations SET json = json_set(json, '$.expireTimer', 30, '$.expireTimerVersion', 3) WHERE id = 'c-alice';
        UPDATE messages SET type = 'timer-notification', json = '{{"flags":2,"expirationTimerUpdate":{{"expireTimer":30,"sourceServiceId":"{ME}","fromSync":false}}}}' WHERE id = 'm12';
    "#,
        current_schema()
    );
    let records = parse(&sql)?;
    let events = of_kind(&records, TIMER_UPDATE_KIND);
    assert_eq!(events.len(), 1);
    let event = events[0];
    assert_eq!(event.json["source"]["id"], "m12");
    assert_eq!(event.json["expire_timer_seconds"], 30);
    assert_eq!(event.json["actor"]["service_id"], ME);
    assert_eq!(event.json["expiration_timer_update"]["fromSync"], false);
    assert!(event.json.get("direction").is_none());
    assert!(event.json.get("state").is_none());
    assert!(
        !messages(&records)
            .iter()
            .any(|record| record.json["source"]["id"] == "m12")
    );
    let chat = records
        .iter()
        .find(|r| r.kind == "mobile.communication.chat" && r.json["chat"]["id"] == "c-alice")
        .unwrap();
    assert_eq!(
        chat.json["chat"]["disappearing_messages"]["expire_timer_seconds"],
        30
    );
    assert_eq!(
        chat.json["chat"]["disappearing_messages"]["expire_timer_version"],
        3
    );
    let timeline = SignalDesktopParser.extract_timeline_events(event);
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].event_type, TIMER_UPDATE_KIND);
    assert_eq!(timeline[0].actor.as_deref(), Some(ME));
    assert_eq!(
        timeline[0].ts_unix_ms,
        event.json["timestamps"]["message"]["unix_ms"]
            .as_i64()
            .unwrap()
    );
    let disabled = parse(&format!(
        "{}\nUPDATE messages SET type = 'timer-notification', json = '{{\"expirationTimerUpdate\":{{\"expireTimer\":0}}}}' WHERE id='m12';",
        current_schema()
    ))?;
    assert_eq!(
        of_kind(&disabled, TIMER_UPDATE_KIND)[0].text,
        "Disappearing messages disabled"
    );
    Ok(())
}

#[test]
fn malformed_native_timer_json_retains_its_source_and_diagnostics() -> Result<()> {
    let sql = format!(
        "{}\nUPDATE messages SET type='timer-notification', json='{{' WHERE id='m12';",
        current_schema()
    );
    for context in [false, true] {
        let (records, issues) = parse_with_issues(&sql, context)?;
        let events = of_kind(&records, TIMER_UPDATE_KIND);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].json["source"]["id"], "m12");
        assert!(events[0].json["expire_timer_seconds"].is_null());
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("messages.json"));
    }
    Ok(())
}

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

fn invoke_with_diagnostics(
    input: ParserInput,
    with_context: bool,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<()> {
    if with_context {
        crate::run_parser_with_options(
            &SignalDesktopParser,
            input,
            ParserOptions::default(),
            sink,
            diagnostic,
        )
    } else {
        SignalDesktopParser.run_into_with_diagnostics(input, sink, diagnostic)
    }
}

fn parse_with_issues(
    sql: &str,
    with_context: bool,
) -> Result<(Vec<ObjectParsed>, Vec<ParserIssue>)> {
    let tmp = tempfile::tempdir()?;
    let db = tmp.path().join("db.sqlite");
    SqliteConnection::create_for_test(&db)?.execute_batch(sql)?;
    let mut objects = Vec::new();
    let mut issues = Vec::new();
    invoke_with_diagnostics(
        ParserInput::Path(db),
        with_context,
        &mut |object| {
            objects.push(object);
            Ok(())
        },
        &mut |issue| {
            issues.push(issue);
            Ok(())
        },
    )?;
    Ok((objects, issues))
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
fn row(n: i64, kind: &str, conv: &str, body: &str, json: &str, columns: &[(&str, &str)]) -> String {
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
            version INTEGER, transitCdnKey TEXT, transitCdnNumber INTEGER, pending INTEGER,
            PRIMARY KEY (messageId, editHistoryIndex, attachmentType, orderInMessage)) STRICT;
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
            ('m10', -1, 'sticker', 0, 300, 'image/webp', 'st/1', NULL, NULL, NULL, NULL),
            ('m18', -1, 'attachment', 0, 5, 'image/png', 'sy/1', 'system.png', NULL, NULL, NULL),
            ('m18', -1, 'attachment', 1, 5, 'image/png', 'sy/2', 'system2.png', NULL, NULL, NULL);
        UPDATE message_attachments SET width = 640, height = 480,
            thumbnailPath = 'ab/first-thumb', thumbnailLocalKey = 'dGh1bWI=',
            digest = 'ZGlnZXN0', version = 2, transitCdnKey = 'cdn-key',
            transitCdnNumber = 3, pending = 0 WHERE path = 'ab/first';
        UPDATE message_attachments SET duration = 12.5 WHERE path = 'ab/second';
        INSERT INTO edited_messages VALUES ('m15', {T0} + 15500, 1, 'c-alice');
        "#
    );
    let read = |status: &'static str| [("readStatus", status), ("sourceServiceId", alice.as_str())];
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

/// Signal declares `messages.id` STRING and `message_attachments.messageId`
/// TEXT. Joined as they are, no index applies and each message scans
/// every attachment row.
#[test]
fn looks_attachments_up_through_the_primary_key() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let conn = SqliteConnection::create_for_test(&tmp.path().join("db.sqlite"))?;
    conn.execute_batch(
        "CREATE TABLE messages (rowid INTEGER PRIMARY KEY ASC, id STRING UNIQUE, json TEXT,
             type STRING, conversationId STRING);
         CREATE TABLE message_attachments (messageId TEXT NOT NULL,
             editHistoryIndex INTEGER NOT NULL, attachmentType TEXT NOT NULL,
             orderInMessage INTEGER NOT NULL, size INTEGER NOT NULL,
             contentType TEXT NOT NULL, path TEXT,
             PRIMARY KEY (messageId, editHistoryIndex, attachmentType, orderInMessage))
             STRICT;",
    )?;
    let mut plan = Vec::new();
    let query = format!("EXPLAIN QUERY PLAN {}", message_query(&conn.schema()?));
    conn.query_rows(&query, |row| {
        plan.extend(row.text(3));
        Ok(())
    })?;
    assert!(
        plan.iter()
            .any(|step| step.starts_with("SEARCH a USING") && step.contains("(messageId=?")),
        "{plan:?}"
    );
    Ok(())
}

/// The last message has no following row to close it.
#[test]
fn emits_the_attachments_of_the_last_message() -> Result<()> {
    let objects = parse(&format!(
        "{}
         INSERT INTO messages (rowid, id, json, type, conversationId, sent_at) VALUES
             (90, 'last', '{{}}', 'incoming', 'c-alice', {T0});
         INSERT INTO message_attachments (messageId, editHistoryIndex, attachmentType,
             orderInMessage, size, contentType, path) VALUES
             ('last', -1, 'attachment', 1, 2, 'image/png', 'zz/second'),
             ('last', -1, 'attachment', 0, 1, 'image/png', 'zz/first'),
             ('last', 0, 'attachment', 0, 3, 'image/png', 'zz/earlier-revision');",
        current_schema()
    ))?;
    let last = objects.len() - 3;
    assert_eq!(objects[last].json["source"]["id"], "last");
    let paths: Vec<_> = objects[last + 1..]
        .iter()
        .map(|record| {
            assert_eq!(record.kind, "mobile.communication.attachment");
            assert_eq!(record.json["message"]["id"], "last");
            record.json["media"]["local_path"].clone()
        })
        .collect();
    assert_eq!(paths, ["zz/first", "zz/second"]);
    Ok(())
}

/// A table the message query cannot read is reported before the
/// conversations are emitted, not after.
#[test]
fn refuses_an_unreadable_attachment_table_before_the_first_record() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let db = tmp.path().join("db.sqlite");
    SqliteConnection::create_for_test(&db)?.execute_batch(
        "CREATE TABLE conversations (id STRING PRIMARY KEY ASC, json TEXT, type STRING);
         CREATE TABLE messages (rowid INTEGER PRIMARY KEY ASC, id STRING UNIQUE, json TEXT,
             type STRING, conversationId STRING);
         CREATE TABLE message_attachments (messageId TEXT PRIMARY KEY, path TEXT)
             WITHOUT ROWID;
         INSERT INTO conversations VALUES ('c1', '{}', 'private');
         INSERT INTO messages VALUES (1, 'm1', '{}', 'incoming', 'c1');",
    )?;
    let (result, objects) = run(ParserInput::Path(db), options(None, None));
    let error = format!("{:#}", result.unwrap_err());
    assert!(
        error.starts_with("cannot read the messages of this database"),
        "{error}"
    );
    assert!(objects.is_empty());
    Ok(())
}

#[test]
fn counts_the_owner_entry_only_when_it_is_alone() {
    let state = |json: &str| outgoing_state(&serde_json::from_str(json).unwrap(), Some("me"));
    // Note to Self.
    assert_eq!(
        state(r#"{"me":{"status":"Read"}}"#),
        (Some(true), Some(true))
    );
    assert_eq!(state(r#"{"me":{"status":"Sent"}}"#), (Some(false), None));
    // The sync to the owner's devices says nothing about the recipient.
    assert_eq!(
        state(r#"{"alice":{"status":"Sent"},"me":{"status":"Read"}}"#),
        (Some(false), None)
    );
    // A recipient without a usable status: unknown, not the owner's state.
    assert_eq!(
        state(r#"{"alice":{},"me":{"status":"Read"}}"#),
        (None, None)
    );
    assert_eq!(state(r#"{}"#), (None, None));
    assert_eq!(state(r#"[]"#), (None, None));
}

#[test]
fn outgoing_receipts_stay_unknown_when_the_owner_is_unidentified() -> Result<()> {
    for change in [
        "DELETE FROM items WHERE id = 'uuid_id';",
        "UPDATE items SET json = '{' WHERE id = 'uuid_id';",
        r#"UPDATE items SET json = '{"value":17}' WHERE id = 'uuid_id';"#,
        r#"UPDATE items SET json = '{"value":""}' WHERE id = 'uuid_id';"#,
        r#"UPDATE items SET json = '{"value":"unmatched.2"}' WHERE id = 'uuid_id';"#,
        "DELETE FROM conversations WHERE id = 'c-me';",
        "DROP TABLE items;",
    ] {
        let objects = parse(&format!("{}\n{change}", current_schema()))?;
        for id in ["m4", "m6", "m17"] {
            let object = message(&objects, id);
            assert!(object["state"]["read"].is_null(), "{change}: {id}");
            assert!(object["state"]["delivered"].is_null(), "{change}: {id}");
        }
        // The raw map remains available even when interpretation is uncertain.
        assert_eq!(
            message(&objects, "m4")["details"]["send_state_by_conversation_id"]["c-me"]["status"],
            "Read"
        );
        assert_eq!(message(&objects, "m1")["state"]["read"], true);
    }
    Ok(())
}

#[test]
fn malformed_json_reports_source_rows_in_both_diagnostic_paths() -> Result<()> {
    let sql = format!(
        r#"{}
        UPDATE items SET json = '{{"value":' WHERE id = 'uuid_id';
        UPDATE conversations SET json = '{{"name":' WHERE id = 'c-alice';
        UPDATE messages SET json = '{{"quote":' WHERE id = 'm3';
        INSERT INTO messages (rowid, id, type, conversationId, json, body,
            sent_at, sourceServiceId, readStatus) VALUES
            (90, 'damaged', 'incoming', 'c-alice', '{{"private-json-marker":',
             'recoverable body', {T0} + 90000, '{ALICE}', 1);
        INSERT INTO message_attachments (messageId, editHistoryIndex, attachmentType,
            orderInMessage, size, contentType, path) VALUES
            ('damaged', -1, 'attachment', 0, 3, 'image/png', 'aa/first'),
            ('damaged', -1, 'attachment', 1, 4, 'text/plain', 'bb/second');"#,
        current_schema()
    );
    for with_context in [false, true] {
        let (objects, issues) = parse_with_issues(&sql, with_context)?;
        assert_eq!(messages(&objects).len(), 18);
        assert_eq!(issues.len(), 4);
        let source = objects[0].json["source"]["path"].as_str().unwrap();
        for (issue, (table, unit, location)) in issues.iter().zip([
            ("items", None, "id \"uuid_id\""),
            ("conversations", Some(2), "rowid 2"),
            ("messages", Some(3), "rowid 3"),
            ("messages", Some(90), "rowid 90"),
        ]) {
            assert!(matches!(
                issue.code,
                crate::core::ParserIssueCode::RecordParse
            ));
            assert_eq!(issue.unit, unit);
            assert!(issue.message.contains(source));
            assert!(issue.message.contains(&format!("{table}.json")));
            assert!(issue.message.contains(location));
            assert!(!issue.message.contains("private-json-marker"));
            assert!(!issue.message.contains("recoverable body"));
        }
        let object = message(&objects, "damaged");
        assert_eq!(object["body"], "recoverable body");
        assert_eq!(object["sender"]["id"], ALICE);
        assert_eq!(object["conversation"]["display_name"], "Alice Smith");
        assert_eq!(object["timestamps"]["message"]["unix_ms"], T0 + 90000);
        assert_eq!(object["state"]["read"], false);
        assert_eq!(object["attachments"].as_array().unwrap().len(), 2);
        let attachments: Vec<_> = of_kind(&objects, "mobile.communication.attachment")
            .into_iter()
            .filter(|object| object.json["message"]["id"] == "damaged")
            .map(|object| object.json["media"]["local_path"].clone())
            .collect();
        assert_eq!(attachments, ["aa/first", "bb/second"]);
    }
    Ok(())
}

#[test]
fn absent_and_json_null_values_do_not_report_decoding_failures() -> Result<()> {
    let sql = format!(
        "{}\nUPDATE items SET json = NULL;
         UPDATE conversations SET json = NULL WHERE id = 'c-bob';
         UPDATE conversations SET json = 'null' WHERE id = 'c-carol';
         UPDATE messages SET json = NULL WHERE id = 'm1';
         UPDATE messages SET json = 'null' WHERE id = 'm2';",
        current_schema()
    );
    for with_context in [false, true] {
        let (objects, issues) = parse_with_issues(&sql, with_context)?;
        assert_eq!(messages(&objects).len(), 17);
        assert!(issues.is_empty());
        assert_eq!(message(&objects, "m1")["body"], "hi");
        assert_eq!(message(&objects, "m2")["body"], "unread one");
    }
    Ok(())
}

#[test]
fn owner_items_without_rowid_preserve_identity_and_diagnostics() -> Result<()> {
    let sql = format!(
        "{}\nALTER TABLE items RENAME TO old_items;
         CREATE TABLE items (id TEXT PRIMARY KEY, json TEXT) WITHOUT ROWID;
         INSERT INTO items SELECT id, json FROM old_items;
         DROP TABLE old_items;",
        current_schema()
    );
    for with_context in [false, true] {
        let (objects, issues) = parse_with_issues(&sql, with_context)?;
        assert!(issues.is_empty());
        assert_eq!(message(&objects, "m4")["state"]["delivered"], true);
        assert!(message(&objects, "m4")["state"]["read"].is_null());
        assert_eq!(message(&objects, "m17")["state"]["read"], true);

        let (objects, issues) = parse_with_issues(
            &format!("{sql}\nUPDATE items SET json = '{{' WHERE id = 'uuid_id';"),
            with_context,
        )?;
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].unit, None);
        assert!(issues[0].message.contains("items.json at id \"uuid_id\""));
        assert!(message(&objects, "m4")["state"]["read"].is_null());
        assert!(message(&objects, "m4")["state"]["delivered"].is_null());
    }
    Ok(())
}

#[test]
fn negative_rowids_are_preserved_without_wrapping_diagnostic_units() -> Result<()> {
    let sql = format!(
        "{}\nUPDATE messages SET rowid = -4, json = '{{' WHERE id = 'm4';",
        current_schema()
    );
    for with_context in [false, true] {
        let (objects, issues) = parse_with_issues(&sql, with_context)?;
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].unit, None);
        assert!(issues[0].message.contains("rowid -4"));
        let object = message(&objects, "m4");
        assert_eq!(object["source"]["rowid"], -4);
        assert_eq!(object["body"], "yo");
    }
    Ok(())
}

#[test]
fn diagnostic_handler_failures_abort_both_paths_at_the_source_row() -> Result<()> {
    for with_context in [false, true] {
        for (table, predicate) in [
            ("items", "id = 'uuid_id'"),
            ("conversations", "id = 'c-alice'"),
            ("messages", "id = 'm3'"),
        ] {
            let tmp = tempfile::tempdir()?;
            let db = tmp.path().join("db.sqlite");
            SqliteConnection::create_for_test(&db)?.execute_batch(&format!(
                "{}\nUPDATE {table} SET json = '{{' WHERE {predicate};",
                current_schema()
            ))?;
            let mut objects = Vec::new();
            let mut issues = 0;
            let error = invoke_with_diagnostics(
                ParserInput::Path(db),
                with_context,
                &mut |object| {
                    objects.push(object);
                    Ok(())
                },
                &mut |_| {
                    issues += 1;
                    anyhow::bail!("diagnostic handler stopped")
                },
            )
            .unwrap_err();
            assert_eq!(error.root_cause().to_string(), "diagnostic handler stopped");
            assert_eq!(issues, 1);
            if table == "messages" {
                assert!(
                    messages(&objects)
                        .iter()
                        .all(|m| m.json["source"]["id"] != "m3")
                );
            } else {
                assert!(objects.is_empty());
            }
        }
    }
    Ok(())
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
    // m18 is a group change: neither the row nor its attachments come out.
    assert!(
        records
            .iter()
            .all(|record| record.json["message"]["id"] != "m18")
    );
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

/// A few bytes cannot be a database, encrypted or not: no key would help.
#[test]
fn rejects_a_fragment_without_asking_for_a_key() {
    for fragment in [&b"SQLite for"[..], b"SQLite format 3", &[0x5a; 511]] {
        let (result, objects) = run(ParserInput::Bytes(fragment.to_vec()), options(None, None));
        let error = result.unwrap_err();
        assert!(error.downcast_ref::<ParserInputError>().is_none());
        assert!(error.to_string().contains("smaller than one database page"));
        assert!(objects.is_empty());
    }
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
        let not_hexadecimal = [b"horse".as_slice(), &[b'z'; 59]].concat();
        for malformed in [b"correct horse battery staple".as_slice(), &not_hexadecimal] {
            let (result, objects) = run(
                ParserInput::Path(db.clone()),
                options(Some(malformed), None),
            );
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
        }
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
