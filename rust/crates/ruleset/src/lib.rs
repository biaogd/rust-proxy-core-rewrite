//! MRS conversion helpers, introduced one behavior and direction at a time.

mod decode;
mod encode;
mod model;
mod source;
#[cfg(test)]
mod tests;

pub use decode::{domain_mrs_to_text, ipcidr_mrs_to_text};
pub use encode::{domain_to_mrs, ipcidr_to_mrs};
pub use model::{RulesetError, SourceFormat};
