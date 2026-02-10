//! Channel boundary enforcement primitives.
//!
//! This module provides fail-closed channel classification and validation
//! surfaces used to prevent non-authoritative actuation inputs.

pub mod enforcement;

pub use enforcement::{
    ChannelBoundaryCheck, ChannelBoundaryDefect, ChannelContextTokenError, ChannelSource,
    ChannelViolationClass, MAX_CHANNEL_DETAIL_LENGTH, decode_channel_context_token,
    derive_channel_source_witness, issue_channel_context_token, validate_channel_boundary,
    verify_channel_source_witness,
};
