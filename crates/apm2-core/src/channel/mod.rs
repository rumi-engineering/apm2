//! Channel boundary enforcement primitives.
//!
//! This module provides fail-closed channel classification and validation
//! surfaces used to prevent non-authoritative actuation inputs.

pub mod enforcement;

pub use enforcement::{
    ChannelBoundaryCheck, ChannelBoundaryDefect, ChannelSource, ChannelViolationClass,
    MAX_CHANNEL_DETAIL_LENGTH, validate_channel_boundary,
};
