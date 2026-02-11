//! Channel boundary enforcement primitives.
//!
//! This module provides fail-closed channel classification and validation
//! surfaces used to prevent non-authoritative actuation inputs.

pub mod enforcement;

pub use enforcement::{
    BoundaryFlowPolicyBinding, ChannelBoundaryCheck, ChannelBoundaryDefect,
    ChannelContextTokenError, ChannelSource, ChannelViolationClass, DeclassificationIntentScope,
    LeakageBudgetReceipt, LeakageEstimatorFamily, MAX_CHANNEL_DETAIL_LENGTH,
    MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH, MAX_LEAKAGE_CONFIDENCE_LABEL_LENGTH,
    RedundancyDeclassificationReceipt, TimingChannelBudget, decode_channel_context_token,
    derive_channel_source_witness, issue_channel_context_token, validate_channel_boundary,
    verify_channel_source_witness,
};
