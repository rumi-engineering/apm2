//! apm2-lab: disposable PASM experiment harness.
//!
//! This crate is intentionally lab-oriented and optimized for falsifiable
//! experiments, replayability, and rapid iteration.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(missing_docs)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::implicit_clone)]
#![allow(clippy::literal_string_with_formatting_args)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::similar_names)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_join)]
#![allow(clippy::use_self)]

pub mod agent;
pub mod closure;
pub mod event;
pub mod harness;
pub mod ledger;
pub mod metrics;
pub mod prompt;
pub mod scoring;
pub mod spec;
pub mod verdict;
pub mod world;
