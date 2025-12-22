use serde_json::Value;
use std::io::{Read, Seek};
use std::path::PathBuf;

/// Represents the result of parsing an object.
///
/// This struct contains metadata about the parser and the kind of object,
/// as well as both the raw text and a parsed JSON representation.
#[derive(Debug, Clone)]
pub struct ObjectParsed {
    /// Name of the parser that produced this result.
    pub parser: &'static str,
    /// Logical kind or type of the parsed object (e.g., "config", "schema").
    pub kind: &'static str,
    /// Original textual representation of the parsed object.
    pub text: String,
    /// Parsed JSON representation of the object.
    pub json: Value,
}

/// Basic information about an available parser.
///
/// This is typically used for discovery and documentation of parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserInfo {
    /// Unique name of the parser.
    pub name: &'static str,
    /// Human-readable description of what the parser does.
    pub description: &'static str,
}

/// Convenience trait alias for types that implement both `Read` and `Seek`.
///
/// This allows trait objects or generics to be expressed in a more concise way.
pub trait ReadSeek: Read + Seek {}

/// Blanket implementation of `ReadSeek` for any type that implements `Read` and `Seek`.
impl<T: Read + Seek> ReadSeek for T {}

/// Different ways to provide input to a parser.
///
/// This enum abstracts over several common input sources so that parsers
/// can operate over paths, in-memory data, or generic `Read + Seek` streams.
pub enum ParserInput<'a> {
    /// Read input from a file system path.
    Path(PathBuf),
    /// Read input from an in-memory byte buffer.
    Bytes(Vec<u8>),
    /// Read input from a generic reader that also supports seeking.
    ReadSeek(Box<dyn ReadSeek + 'a>),
}
