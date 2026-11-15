//! Parsers for desktop messaging applications whose on-disk format is the same
//! across operating systems (as opposed to the macOS- or mobile-specific
//! artefacts in the sibling modules).

pub mod signal;

pub use signal::SignalDesktopParser;
