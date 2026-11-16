//! Windows artefact parser entry points.

pub mod evtx;
pub mod pe;
pub mod pml;

pub use evtx::WindowsEvtxParser;
pub use pe::WindowsPeParser;
pub use pml::WindowsPmlParser;
