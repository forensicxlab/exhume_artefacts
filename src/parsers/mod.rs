pub mod evtx;
use crate::core::Parser;
use std::{collections::HashMap, sync::Arc};

pub type ParserRegistry = HashMap<&'static str, Arc<dyn Parser>>;

pub fn build_registry() -> ParserRegistry {
    let mut m: ParserRegistry = HashMap::new();

    m.insert(
        "windows_evtx",
        Arc::new(evtx::WindowsEvtxParser::default()) as Arc<dyn Parser>,
    );

    m
}
