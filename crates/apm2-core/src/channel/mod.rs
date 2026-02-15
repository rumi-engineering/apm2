//! Channel boundary enforcement primitives.
//!
//! This module provides fail-closed channel classification and validation
//! surfaces used to prevent non-authoritative actuation inputs.

pub mod enforcement;

pub use enforcement::{
    BoundaryFlowPolicyBinding, ChannelBoundaryCheck, ChannelBoundaryDefect,
    ChannelContextTokenError, ChannelSource, ChannelViolationClass, DeclassificationIntentScope,
    DisclosurePolicyBinding, ExpectedTokenBinding, LeakageBudgetReceipt, LeakageEstimatorFamily,
    MAX_CHANNEL_DETAIL_LENGTH, MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH,
    MAX_DISCLOSURE_PHASE_ID_LENGTH, MAX_DISCLOSURE_STATE_REASON_LENGTH,
    MAX_LEAKAGE_CONFIDENCE_LABEL_LENGTH, MAX_TOKEN_BOUNDARY_ID_LENGTH,
    RedundancyDeclassificationReceipt, TimingChannelBudget, TokenBindingV1,
    decode_channel_context_token, decode_channel_context_token_with_binding,
    derive_channel_source_witness, issue_channel_context_token,
    issue_channel_context_token_with_token_binding, validate_channel_boundary,
    verify_channel_source_witness,
};
