use anyhow::Result;
use clap::*;
use exhume_artefacts::core::{ObjectParsed, ParserInput};
use exhume_artefacts::parsers::build_registry;
use log::LevelFilter;

fn main() -> Result<()> {
    let matches = Command::new("exhume_artefacts")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Run a named artefact parser on a file and output JSONL.")
        .arg(
            Arg::new("list_parsers")
                .long("list-parsers")
                .help("List available parsers (name + description) and exit.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_parser(value_parser!(String))
                .required_unless_present("list_parsers")
                .help("Path to input file"),
        )
        .arg(
            Arg::new("parser")
                .short('p')
                .long("parser")
                .value_parser(value_parser!(String))
                .required_unless_present("list_parsers")
                .help("Parser name"),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info"),
        )
        .get_matches();

    // Logger (same pattern as examples)
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

    let registry = build_registry();

    if matches.get_flag("list_parsers") {
        println!("available parsers:");
        for p in exhume_artefacts::list_parsers(&registry) {
            println!("  {:<20} {}", p.name, p.description);
        }
        return Ok(());
    }

    let file_path = matches.get_one::<String>("file").unwrap();
    let parser_name = matches.get_one::<String>("parser").unwrap();

    let parser = registry
        .get(parser_name.as_str())
        .ok_or_else(|| anyhow::anyhow!("unknown parser: {parser_name}"))?;

    let mut count = 0usize;
    let mut sink = |obj: ObjectParsed| -> Result<()> {
        count += 1;
        println!("{}", obj.json);
        Ok(())
    };

    parser.run_into(ParserInput::Path(file_path.into()), &mut sink)?;

    eprintln!("done: emitted {count} objects");
    Ok(())
}
