/// Core parsing traits, types, and shared functionality.
pub mod core;
/// Concrete parser implementations and the parser registry.
pub mod parsers;

use crate::parsers::ParserRegistry;
use anyhow::Result;
pub use core::{ObjectParsed, Parser, ParserInfo, ParserInput};

/// Return a sorted list of metadata describing all registered parsers.
///
/// The returned vector is sorted in ascending order by parser name.
///
/// # Arguments
///
/// * `registry` - The registry containing all available parsers.
pub fn list_parsers(registry: &ParserRegistry) -> Vec<ParserInfo> {
    let mut out: Vec<ParserInfo> = registry
        .values()
        .map(|p| ParserInfo {
            name: p.name(),
            description: p.description(),
        })
        .collect();

    out.sort_by(|a, b| a.name.cmp(b.name));
    out
}

/// Run a parser selected by name and stream its parsed objects to a sink.
///
/// # Arguments
///
/// * `registry` - The registry used to look up the parser by name.
/// * `name` - The name of the parser to run.
/// * `input` - The input data that will be provided to the parser.
/// * `sink` - A callback that will be invoked for each parsed object.
///
/// # Errors
///
/// Returns an error if:
/// * No parser with the given `name` exists in the registry.
/// * The selected parser fails during execution.
pub fn run_parser_by_name(
    registry: &ParserRegistry,
    name: &str,
    input: ParserInput,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let p = registry
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("unknown parser: {name}"))?;

    p.run_into(input, sink)
}
