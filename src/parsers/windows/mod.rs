//! Windows artefact parser entry points.

pub mod dpapi;
pub mod evtx;
pub mod pe;
pub mod pml;

pub use dpapi::WindowsDpapiMasterKeyParser;
pub use evtx::WindowsEvtxParser;
pub use pe::WindowsPeParser;
pub use pml::WindowsPmlParser;

#[cfg(test)]
mod tests;
