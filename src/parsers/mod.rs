pub mod evtx;
pub mod mobile;
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
        Arc::new(pml::WindowsPmlParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_whatsapp",
        Arc::new(mobile::IosWhatsAppParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_imessage",
        Arc::new(mobile::IosIMessageParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_callhistory",
        Arc::new(mobile::IosCallHistoryParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_contacts",
        Arc::new(mobile::IosContactsParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_safari",
        Arc::new(mobile::IosSafariParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_tcc",
        Arc::new(mobile::IosTccParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_knowledgec",
        Arc::new(mobile::IosKnowledgeCParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_routined",
        Arc::new(mobile::IosRoutinedParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_interactionc",
        Arc::new(mobile::IosInteractionCParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_datausage",
        Arc::new(mobile::IosDataUsageParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_photos",
        Arc::new(mobile::IosPhotosParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_calendar",
        Arc::new(mobile::IosCalendarParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_mail",
        Arc::new(mobile::IosMailParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_notes",
        Arc::new(mobile::IosNotesParser) as Arc<dyn Parser>,
    );

    m
}
