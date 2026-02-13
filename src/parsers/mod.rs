pub mod evtx;
pub mod pe;
pub mod pml;
use crate::core::Parser;
use std::{collections::HashMap, sync::Arc};

pub type ParserRegistry = HashMap<&'static str, Arc<dyn Parser>>;

pub fn build_registry() -> ParserRegistry {
    let mut m: ParserRegistry = HashMap::new();

    m.insert(
        "windows_evtx",
        Arc::new(evtx::WindowsEvtxParser::default()) as Arc<dyn Parser>,
    );

    m.insert(
        "windows_pe",
        Arc::new(pe::WindowsPeParser::default()) as Arc<dyn Parser>,
    );

    m.insert(
        "windows_pml",
        Arc::new(pml::WindowsPmlParser::default()) as Arc<dyn Parser>,
    );

    m
}
