//! Validation support for kernel events.
//!
//! This module provides the [`Validate`] trait for ensuring event messages
//! are well-formed and adhere to security constraints (e.g., bounded length).
//!
//! # Security
//!
//! Validation is a critical defense-in-depth layer that prevents
//! denial-of-service attacks via unbounded deserialization and ensures
//! data integrity.

use super::DefectRecorded;

/// Trait for validating event messages.
pub trait Validate {
    /// Validates the message, returning `Ok(())` if valid or an error
    /// description.
    ///
    /// # Errors
    ///
    /// Returns a `String` describing the validation failure if the message
    /// does not meet required constraints (e.g., field length limits).
    fn validate(&self) -> Result<(), String>;
}

// =============================================================================
// Validation Implementations
// =============================================================================

impl Validate for DefectRecorded {
    fn validate(&self) -> Result<(), String> {
        // TCK-00307: Validation bounds for DefectRecorded
        // Prevents DoS via unbounded strings/bytes.

        // defect_id: max 128 chars
        if self.defect_id.len() > 128 {
            return Err(format!(
                "defect_id too long: {} > 128",
                self.defect_id.len()
            ));
        }
        if self.defect_id.is_empty() {
            return Err("defect_id must be non-empty".to_string());
        }

        // defect_type: max 64 chars
        if self.defect_type.len() > 64 {
            return Err(format!(
                "defect_type too long: {} > 64",
                self.defect_type.len()
            ));
        }
        if self.defect_type.is_empty() {
            return Err("defect_type must be non-empty".to_string());
        }

        // cas_hash: must be exactly 32 bytes (BLAKE3)
        if self.cas_hash.len() != 32 {
            return Err(format!(
                "cas_hash must be 32 bytes, got {}",
                self.cas_hash.len()
            ));
        }

        // work_id: max 128 chars
        if self.work_id.len() > 128 {
            return Err(format!("work_id too long: {} > 128", self.work_id.len()));
        }
        // work_id can be empty? Protocol usually requires it, but maybe for some
        // defects it's not applicable. The proto says "if applicable". Let's
        // allow empty if permitted, but bounded if present.

        // severity: max 16 chars
        if self.severity.len() > 16 {
            return Err(format!("severity too long: {} > 16", self.severity.len()));
        }
        if self.severity.is_empty() {
            return Err("severity must be non-empty".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::DefectSource;

    #[test]
    fn test_defect_recorded_validation() {
        let valid = DefectRecorded {
            defect_id: "DEF-001".to_string(),
            defect_type: "TYPE".to_string(),
            cas_hash: vec![0u8; 32],
            source: DefectSource::DivergenceWatchdog as i32,
            work_id: "W-123".to_string(),
            severity: "S0".to_string(),
            detected_at: 0,
            time_envelope_ref: None,
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_defect_recorded_validation_failures() {
        let mut invalid = DefectRecorded {
            defect_id: "x".repeat(129), // Too long
            defect_type: "TYPE".to_string(),
            cas_hash: vec![0u8; 32],
            source: DefectSource::DivergenceWatchdog as i32,
            work_id: "W-123".to_string(),
            severity: "S0".to_string(),
            detected_at: 0,
            time_envelope_ref: None,
        };
        assert!(invalid.validate().is_err());

        invalid.defect_id = "DEF-001".to_string();
        invalid.cas_hash = vec![0u8; 31]; // Too short
        assert!(invalid.validate().is_err());
    }
}
