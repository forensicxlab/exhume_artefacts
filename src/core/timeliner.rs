/// A single normalized temporal event extracted from a parsed artifact object.
///
/// Parsers produce these via [`crate::Parser::extract_timeline_events`] so the
/// indexer can write a unified `timeline_events` table without knowing each
/// parser's JSON schema.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    /// Unix timestamp in milliseconds.
    pub ts_unix_ms: i64,
    /// Dot-namespaced event type (e.g. `"windows.evtx.event"`, `"mobile.communication.message"`).
    pub event_type: &'static str,
    /// Short human-readable summary of the event.
    pub description: Option<String>,
    /// Actor associated with the event (user, process, contact identifier, etc.).
    pub actor: Option<String>,
}
