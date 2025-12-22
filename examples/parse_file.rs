use clap::*;
use exhume_artefacts::core::ParserInput;
use exhume_artefacts::parsers::build_registry;
use log::LevelFilter;

/// Entry point for the `parse_file` CLI.
///
/// This binary parses a standalone file using a named parser from the
/// `exhume_artefacts` registry and prints one JSON object per line (JSONL)
/// to stdout.
///
/// # Errors
///
/// Returns an error if:
/// - CLI argument parsing fails (handled by `clap` and will abort before this),
/// - the requested parser name is not found in the registry,
/// - the selected parser fails while processing the input file.
fn main() -> anyhow::Result<()> {
    // Build the CLI interface and parse command-line arguments.
    let matches = Command::new("parse_file")
        .about("Parse a standalone file with a named parser and output JSONL.")
        .arg(
            Arg::new("list_parsers")
                .long("list-parsers")
                .help("List available parsers (name + description) and exit.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("file")
                .value_parser(value_parser!(String))
                .required_unless_present("list_parsers"),
        )
        .arg(
            Arg::new("parser")
                .value_parser(value_parser!(String))
                .required_unless_present("list_parsers"),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info"),
        )
        .get_matches();

    // Configure the logger (same pattern as `exhume_body` / `exhume_filesystem`).
    // The log level is taken from the `--log-level` argument.
    let log_level_str = matches.get_one::<String>("log_level").unwrap();
    let level_filter = match log_level_str.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(level_filter).init();

    // Build the parser registry that maps parser names to parser implementations.
    let registry = build_registry();

    // If `--list-parsers` is provided, list all available parsers and exit.
    if matches.get_flag("list_parsers") {
        println!("available parsers:");
        for p in exhume_artefacts::list_parsers(&registry) {
            println!("  {:<20} {}", p.name, p.description);
        }
        return Ok(());
    }

    // Extract the target file path and parser name from the CLI arguments.
    let file = matches.get_one::<String>("file").unwrap();
    let parser_name = matches.get_one::<String>("parser").unwrap();

    // Look up the requested parser in the registry, returning an error
    // if the parser name is not known.
    let parser = registry
        .get(parser_name.as_str())
        .ok_or_else(|| anyhow::anyhow!("unknown parser: {parser_name}"))?;

    // Run the parser on the given file path and emit each parsed object as a
    // single JSON line to stdout.
    parser.run_into(ParserInput::Path(file.into()), &mut |obj| {
        println!("{}", obj.json);
        Ok(())
    })?;

    Ok(())
}
