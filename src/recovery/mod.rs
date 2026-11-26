//! Reusable application-key recovery. Callers supply acquired bytes and own
//! discovery, credential prompts, source associations and secret lifetimes.

pub mod signal;
#[cfg(test)]
mod tests;
