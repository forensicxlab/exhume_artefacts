-- Synthetic Signal schema and records, preserved from the existing desktop parser test.

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

        INSERT INTO items VALUES ('uuid_id', '{"value":"aaaaaaaa-0000-4000-8000-000000000001.2"}');
        INSERT INTO conversations (id, json, type, serviceId, e164, active_at) VALUES
            ('c-me', '{"profileName":"Owner"}', 'private', 'aaaaaaaa-0000-4000-8000-000000000001', '+15550000001', 1700000000000);
        INSERT INTO conversations (id, json, type, serviceId, e164, profileFullName, active_at)
            VALUES ('c-alice',
            '{"name":"Alice Example","profileName":"Alice","profileFamilyName":"Smith"}',
            'private', 'bbbbbbbb-0000-4000-8000-000000000002', '+15550000002', 'Alice Smith', 1700000000000 + 1000);
        INSERT INTO conversations (id, json, type, serviceId) VALUES
            ('c-bob', '{"profileName":"Bob","profileFamilyName":"Jones"}', 'private', 'cccccccc-0000-4000-8000-000000000003'),
            ('c-carol', '{"nicknameGivenName":"Caz","profileName":"Carol","username":"carol.01"}',
             'private', 'dddddddd-0000-4000-8000-000000000004');
        INSERT INTO conversations (id, json, type, groupId, active_at) VALUES ('c-team',
            '{"name":"Team","membersV2":[{"aci":"aaaaaaaa-0000-4000-8000-000000000001"},{"aci":"bbbbbbbb-0000-4000-8000-000000000002"},{"aci":"cccccccc-0000-4000-8000-000000000003"}]}',
            'group', 'Z3JvdXA=', 1700000000000 + 9000);

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
        INSERT INTO edited_messages VALUES ('m15', 1700000000000 + 15500, 1, 'c-alice');
        INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, seenStatus, sourceServiceId, source) VALUES (1, 'm1', 'incoming', 'c-alice', 'hi', '{}', 1700000001000, 1700000001000, 0, 2, 'bbbbbbbb-0000-4000-8000-000000000002', '+15550000002');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId) VALUES (2, 'm2', 'incoming', 'c-alice', 'unread one', '{}', 1700000002000, 1700000002000, 1, 'bbbbbbbb-0000-4000-8000-000000000002');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId, expireTimer) VALUES (3, 'm3', 'incoming', 'c-alice', NULL, '{"quote":{"id":1700000001000,"text":"hi"}}', 1700000003000, 1700000003000, 2, 'bbbbbbbb-0000-4000-8000-000000000002', 3600);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms) VALUES (4, 'm4', 'outgoing', 'c-alice', 'yo', '{"sendStateByConversationId":{"c-alice":{"status":"Delivered"},"c-me":{"status":"Read"}},"reactions":[{"fromId":"c-alice","emoji":"👍","timestamp":1700000004500}]}', 1700000004000, 1700000004000);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId) VALUES (5, 'm5', 'incoming', 'c-team', 'from bob', '{}', 1700000005000, 1700000005000, 0, 'cccccccc-0000-4000-8000-000000000003');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms) VALUES (6, 'm6', 'outgoing', 'c-team', 'welcome', '{"sendStateByConversationId":{"c-alice":{"status":"Viewed"},"c-bob":{"status":"Pending"},"c-me":{"status":"Sent"}}}', 1700000006000, 1700000006000);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, isErased) VALUES (7, 'm7', 'outgoing', 'c-bob', NULL, '{"sendStateByConversationId":{"c-bob":{"status":"Sent"}},"deletedForEveryone":true}', 1700000007000, 1700000007000, 1);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, isErased, isViewOnce) VALUES (8, 'm8', 'outgoing', 'c-bob', NULL, '{"sendStateByConversationId":{"c-bob":{"status":"Delivered"}}}', 1700000008000, 1700000008000, 1, 1);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId) VALUES (9, 'm9', 'incoming', 'c-alice', 'odd', '{}', 1700000009000, 1700000009000, 99, 'bbbbbbbb-0000-4000-8000-000000000002');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId) VALUES (10, 'm10', 'incoming', 'c-alice', NULL, '{"sticker":{"packId":"p","stickerId":3,"emoji":"😀"}}', 1700000010000, 1700000010000, 0, 'bbbbbbbb-0000-4000-8000-000000000002');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId) VALUES (11, 'm11', 'incoming', 'c-alice', NULL, '{"poll":{"question":"Where do we meet?","options":["Park","Cafe"],"allowMultiple":false}}', 1700000011000, 1700000011000, 0, 'bbbbbbbb-0000-4000-8000-000000000002');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms) VALUES (12, 'm12', 'outgoing', 'c-alice', NULL, '{"flags":2,"expirationTimerUpdate":{"expireTimer":3600}}', 1700000012000, 1700000012000);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId) VALUES (13, 'm13', 'incoming', 'c-alice', NULL, '{"contact":[{"name":{"givenName":"Dana","familyName":"Lee"},"number":[{"value":"+15550000009"}]}]}', 1700000013000, 1700000013000, 0, 'bbbbbbbb-0000-4000-8000-000000000002');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms) VALUES (14, 'm14', 'outgoing', 'c-alice', 'meet at 6', '{"sendStateByConversationId":{"c-alice":{"status":"Read"}},"editMessageTimestamp":1700000014500,"editHistory":[{"body":"meet at 6","timestamp":1700000014500,"sendStateByConversationId":{"c-alice":{"status":"Sent"}}},{"body":"meet at 5","timestamp":1700000014000,"sendStateByConversationId":{"c-alice":{"status":"Read"}}}]}', 1700000014000, 1700000014000);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId) VALUES (15, 'm15', 'incoming', 'c-alice', 'new text', '{"editMessageTimestamp":1700000015500,"editHistory":[{"body":"new text","timestamp":1700000015500,"readStatus":1},{"body":"old text","timestamp":1700000015000,"readStatus":0}]}', 1700000015000, 1700000015000, 0, 'bbbbbbbb-0000-4000-8000-000000000002');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms, readStatus, sourceServiceId, storyId) VALUES (16, 'm16', 'incoming', 'c-team', 'nice story', '{}', 1700000016000, 1700000016000, 0, 'cccccccc-0000-4000-8000-000000000003', 'story-1');
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms) VALUES (17, 'm17', 'outgoing', 'c-me', 'note', '{"sendStateByConversationId":{"c-me":{"status":"Read"}}}', 1700000017000, 1700000017000);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms) VALUES (18, 'm18', 'group-v2-change', 'c-team', NULL, '{}', 1700000018000, 1700000018000);
INSERT INTO messages (rowid, id, type, conversationId, body, json, sent_at, received_at_ms) VALUES (19, 'm19', 'call-history', 'c-alice', NULL, '{}', 1700000019000, 1700000019000);
