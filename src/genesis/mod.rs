//! NOVARA Genesis configuration.
//!
//! Defines the initial identity and configuration of a NOVARA network.

/// Current supported genesis format version.
pub const GENESIS_VERSION: u32 = 1;

/// NOVARA Network ID is exactly 32 bytes.
pub const NETWORK_ID_LENGTH: usize = 32;

/// Unique identity for a NOVARA network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkId([u8; NETWORK_ID_LENGTH]);

impl NetworkId {
    /// Creates a Network ID from exactly 32 bytes.
    pub fn new(bytes: [u8; NETWORK_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw Network ID bytes.
    pub fn as_bytes(&self) -> &[u8; NETWORK_ID_LENGTH] {
        &self.0
    }
}

/// Initial NOVARA application genesis configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisConfig {
    /// Genesis format version.
    pub version: u32,

    /// Unique identity of this NOVARA network.
    pub network_id: NetworkId,
}

impl GenesisConfig {
    /// Creates a genesis configuration.
    pub fn new(version: u32, network_id: NetworkId) -> Result<Self, GenesisError> {
        if version != GENESIS_VERSION {
            return Err(GenesisError::UnsupportedVersion(version));
        }

        Ok(Self {
            version,
            network_id,
        })
    }
}

/// Errors returned during genesis validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenesisError {
    UnsupportedVersion(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_genesis_version() {
        let network_id = NetworkId::new([1u8; NETWORK_ID_LENGTH]);

        let result = GenesisConfig::new(GENESIS_VERSION, network_id);

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_unsupported_genesis_version() {
        let network_id = NetworkId::new([1u8; NETWORK_ID_LENGTH]);

        let result = GenesisConfig::new(2, network_id);

        assert_eq!(result, Err(GenesisError::UnsupportedVersion(2)));
    }
}
