//! Emergency key-rotation receipts and helper flow wiring for HSM providers.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::hsm::{HsmError, HsmProvider, HsmProviderType, HsmResult};

/// Schema identifier for [`KeyRotationReceiptV1`].
pub const KEY_ROTATION_RECEIPT_V1_SCHEMA: &str = "apm2.key_rotation_receipt.v1";

/// Maximum allowed key identifier length for rotation receipts.
pub const MAX_ROTATION_KEY_ID_LEN: usize = 128;

/// Errors produced by key-rotation receipt validation.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRotationReceiptError {
    /// A key identifier is empty.
    #[error("field '{field}' must be non-empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// A key identifier exceeded its configured bound.
    #[error("field '{field}' exceeds max length: {actual} > {max}")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual field length.
        actual: usize,
        /// Maximum field length.
        max: usize,
    },
    /// Overlap validity interval is invalid.
    #[error(
        "invalid overlap validity interval: overlap_valid_until_ms ({overlap_valid_until_ms}) < overlap_valid_from_ms ({overlap_valid_from_ms})"
    )]
    InvalidOverlapInterval {
        /// Overlap start timestamp.
        overlap_valid_from_ms: u64,
        /// Overlap end timestamp.
        overlap_valid_until_ms: u64,
    },
}

/// Receipt emitted after emergency key rotation with overlapping validity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationReceiptV1 {
    /// Previous key identifier.
    pub old_key_id: String,
    /// Newly rotated key identifier.
    pub new_key_id: String,
    /// Overlap validity window start.
    pub overlap_valid_from_ms: u64,
    /// Overlap validity window end.
    pub overlap_valid_until_ms: u64,
    /// Rotation execution timestamp.
    pub rotated_at_ms: u64,
    /// HSM provider profile that executed the rotation.
    pub provider_type: HsmProviderType,
}

impl KeyRotationReceiptV1 {
    /// Returns this receipt schema identifier.
    #[must_use]
    pub const fn schema() -> &'static str {
        KEY_ROTATION_RECEIPT_V1_SCHEMA
    }

    /// Validates receipt structural and bounded-field constraints.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRotationReceiptError`] when validation fails.
    pub fn validate(&self) -> Result<(), KeyRotationReceiptError> {
        validate_non_empty_bounded("old_key_id", &self.old_key_id, MAX_ROTATION_KEY_ID_LEN)?;
        validate_non_empty_bounded("new_key_id", &self.new_key_id, MAX_ROTATION_KEY_ID_LEN)?;
        if self.overlap_valid_until_ms < self.overlap_valid_from_ms {
            return Err(KeyRotationReceiptError::InvalidOverlapInterval {
                overlap_valid_from_ms: self.overlap_valid_from_ms,
                overlap_valid_until_ms: self.overlap_valid_until_ms,
            });
        }
        Ok(())
    }

    /// Returns `true` if the overlap window includes `timestamp_ms`.
    #[must_use]
    pub const fn overlaps_at(&self, timestamp_ms: u64) -> bool {
        self.overlap_valid_from_ms <= timestamp_ms && timestamp_ms <= self.overlap_valid_until_ms
    }
}

/// Rotates `old_key_id` via [`HsmProvider::rotate_key`] and emits a receipt
/// binding overlapping validity metadata.
///
/// # Arguments
///
/// - `hsm`: HSM provider implementation.
/// - `old_key_id`: Existing key to rotate.
/// - `rotated_at_ms`: Rotation timestamp (milliseconds).
/// - `overlap_valid_until_ms`: End of overlap validity interval.
///
/// # Errors
///
/// Returns provider errors from [`HsmProvider::rotate_key`] and validates that
/// the produced receipt has a valid overlap interval.
pub async fn rotate_key_with_overlapping_validity(
    hsm: &dyn HsmProvider,
    old_key_id: &str,
    rotated_at_ms: u64,
    overlap_valid_until_ms: u64,
) -> HsmResult<KeyRotationReceiptV1> {
    let new_key_id = hsm.rotate_key(old_key_id).await?;
    let receipt = KeyRotationReceiptV1 {
        old_key_id: old_key_id.to_string(),
        new_key_id,
        overlap_valid_from_ms: rotated_at_ms,
        overlap_valid_until_ms,
        rotated_at_ms,
        provider_type: hsm.provider_type(),
    };
    receipt
        .validate()
        .map_err(|error| HsmError::RotationFailed {
            message: error.to_string(),
        })?;
    Ok(receipt)
}

/// Rotates a key and computes overlap window end from a duration.
///
/// # Errors
///
/// Returns [`HsmError`] if rotation fails or overlap arithmetic overflows.
pub async fn rotate_key_with_overlap_duration(
    hsm: &dyn HsmProvider,
    old_key_id: &str,
    rotated_at_ms: u64,
    overlap_duration_ms: u64,
) -> HsmResult<KeyRotationReceiptV1> {
    let overlap_valid_until_ms =
        rotated_at_ms
            .checked_add(overlap_duration_ms)
            .ok_or_else(|| HsmError::RotationFailed {
                message: "overlap duration arithmetic overflow".to_string(),
            })?;
    rotate_key_with_overlapping_validity(hsm, old_key_id, rotated_at_ms, overlap_valid_until_ms)
        .await
}

const fn validate_non_empty_bounded(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), KeyRotationReceiptError> {
    if value.is_empty() {
        return Err(KeyRotationReceiptError::EmptyField { field });
    }
    if value.len() > max_len {
        return Err(KeyRotationReceiptError::FieldTooLong {
            field,
            actual: value.len(),
            max: max_len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hsm::{HsmConfig, HsmProvider, SoftwareHsmProvider};

    #[tokio::test]
    async fn rotate_key_with_overlap_emits_valid_receipt() {
        let provider = SoftwareHsmProvider::new(HsmConfig::software());
        provider.connect().await.expect("provider should connect");
        provider
            .generate_key("validator-key")
            .await
            .expect("key generation should succeed");

        let receipt =
            rotate_key_with_overlapping_validity(&provider, "validator-key", 1_000, 2_000)
                .await
                .expect("rotation should succeed");

        assert_eq!(receipt.old_key_id, "validator-key");
        assert_eq!(receipt.overlap_valid_from_ms, 1_000);
        assert_eq!(receipt.overlap_valid_until_ms, 2_000);
        assert!(receipt.overlaps_at(1_500));
    }
}
