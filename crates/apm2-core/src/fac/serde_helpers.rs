//! Serde helpers for FAC types.
//!
//! This module provides custom serde serialization/deserialization helpers
//! for common patterns in FAC event types.

/// Serde helper for `Option<[u8; 32]>` fields that need to serialize as raw
/// bytes.
///
/// This helper is used for backward-compatible optional hash fields
/// (TCK-00326). When the field is `None`, it is skipped in serialization. When
/// deserializing, missing fields become `None`.
pub mod option_hash32 {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize `Option<[u8; 32]>` as raw bytes or skip if None.
    ///
    /// # Errors
    ///
    /// Returns an error if the serializer fails.
    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_bytes(bytes),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize `Option<[u8; 32]>` from raw bytes or None.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is neither 32 bytes nor empty.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        match opt {
            Some(buf) if buf.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&buf);
                Ok(Some(arr))
            },
            Some(buf) if buf.is_empty() => Ok(None),
            Some(_) => Err(serde::de::Error::custom("expected 32 bytes or empty")),
            None => Ok(None),
        }
    }
}
