//! Parser identifiers are independent of the canonical Rust module paths.

use exhume_artefacts::parsers;

#[test]
fn registry_retains_identifiers_used_by_cli_and_indexer_rules() {
    let registry: parsers::ParserRegistry = parsers::build_registry();
    let mut names: Vec<_> = registry.keys().copied().collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "desktop_signal",
            "linux_gnome_keyring",
            "linux_kwallet",
            "macos_app_bundle",
            "macos_chromium",
            "macos_container_registration",
            "macos_firefox",
            "macos_imessage",
            "macos_install_history",
            "macos_keychain",
            "macos_launchd",
            "macos_loginwindow",
            "macos_network",
            "macos_package_receipt",
            "macos_quarantine",
            "macos_safari",
            "macos_sharedfilelist",
            "macos_spotlight",
            "macos_whatsapp",
            "mobile_android_sms",
            "mobile_ios_app_container",
            "mobile_ios_app_manifest",
            "mobile_ios_calendar",
            "mobile_ios_callhistory",
            "mobile_ios_contacts",
            "mobile_ios_datausage",
            "mobile_ios_frontboard",
            "mobile_ios_iconstate",
            "mobile_ios_imessage",
            "mobile_ios_interactionc",
            "mobile_ios_knowledgec",
            "mobile_ios_mail",
            "mobile_ios_mobileinstallation_log",
            "mobile_ios_notes",
            "mobile_ios_photos",
            "mobile_ios_routined",
            "mobile_ios_safari",
            "mobile_ios_tcc",
            "mobile_ios_whatsapp",
            "windows_dpapi_masterkey",
            "windows_evtx",
            "windows_pe",
            "windows_pml",
        ]
    );
    for (name, parser) in &registry {
        assert_eq!(*name, parser.name());
    }
}
