//! NOVARA Genesis configuration.
//!
//! Defines the initial identity and configuration of a NOVARA network.

/// Current supported genesis format version.
pub const GENESIS_VERSION: u32 = 1;

/// NOVARA Network ID is exactly 32 bytes.
pub const NETWORK_ID_LENGTH: usize = 32;

/// Genesis V1 magic bytes: NVRGEN followed by two zero bytes.
pub const GENESIS_MAGIC: [u8; 8] = *b"NVRGEN\0\0";

/// Exact encoded Genesis V1 length.
pub const GENESIS_V1_LENGTH: usize = 44;

/// Unique identity for a NOVARA network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkId([u8; NETWORK_ID_LENGTH]);

impl NetworkId {
    /// Creates a Network ID from exactly 32 bytes.
    pub fn new(bytes: [u8; NETWORK_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Generates a cryptographically secure random Network ID.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; NETWORK_ID_LENGTH];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
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

    /// Encodes Genesis V1 into its exact 44-byte representation.
    pub fn encode(&self) -> Result<[u8; GENESIS_V1_LENGTH], GenesisError> {
        if self.version != GENESIS_VERSION {
            return Err(GenesisError::UnsupportedVersion(self.version));
        }

        let mut encoded = [0u8; GENESIS_V1_LENGTH];

        encoded[..8].copy_from_slice(&GENESIS_MAGIC);
        encoded[8..12].copy_from_slice(&self.version.to_be_bytes());
        encoded[12..44].copy_from_slice(self.network_id.as_bytes());

        Ok(encoded)
    }

    /// Decodes and validates Genesis V1.
    pub fn decode(bytes: &[u8]) -> Result<Self, GenesisError> {
        if bytes.len() != GENESIS_V1_LENGTH {
            return Err(GenesisError::InvalidLength {
                expected: GENESIS_V1_LENGTH,
                actual: bytes.len(),
            });
        }

        if bytes[..8] != GENESIS_MAGIC {
            return Err(GenesisError::InvalidMagic);
        }

        let version = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| {
            GenesisError::InvalidLength {
                expected: GENESIS_V1_LENGTH,
                actual: bytes.len(),
            }
        })?);

        let network_id_bytes: [u8; NETWORK_ID_LENGTH] =
            bytes[12..44]
                .try_into()
                .map_err(|_| GenesisError::InvalidLength {
                    expected: GENESIS_V1_LENGTH,
                    actual: bytes.len(),
                })?;

        let network_id = NetworkId::new(network_id_bytes);

        Self::new(version, network_id)
    }
}

/// Errors returned during genesis validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenesisError {
    UnsupportedVersion(u32),
    InvalidMagic,
    InvalidLength { expected: usize, actual: usize },
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

    #[test]
    fn generates_secure_network_id() {
        let network_id = NetworkId::generate();

        assert!(network_id.is_ok());

        let network_id = network_id.unwrap();

        assert_eq!(network_id.as_bytes().len(), NETWORK_ID_LENGTH);
    }

    #[test]
    fn encodes_genesis_into_exactly_44_bytes() {
        let network_id = NetworkId::new([7u8; NETWORK_ID_LENGTH]);
        let genesis = GenesisConfig::new(GENESIS_VERSION, network_id).unwrap();

        let encoded = genesis.encode().unwrap();

        assert_eq!(encoded.len(), GENESIS_V1_LENGTH);
        assert_eq!(&encoded[..8], &GENESIS_MAGIC);
        assert_eq!(&encoded[8..12], &GENESIS_VERSION.to_be_bytes());
        assert_eq!(&encoded[12..44], network_id.as_bytes());
    }

    #[test]
    fn decodes_genesis_and_preserves_network_id() {
        let network_id = NetworkId::new([9u8; NETWORK_ID_LENGTH]);
        let genesis = GenesisConfig::new(GENESIS_VERSION, network_id).unwrap();

        let encoded = genesis.encode().unwrap();
        let decoded = GenesisConfig::decode(&encoded).unwrap();

        assert_eq!(decoded, genesis);
    }

    #[test]
    fn rejects_incorrect_genesis_length() {
        let result = GenesisConfig::decode(&[0u8; 43]);

        assert_eq!(
            result,
            Err(GenesisError::InvalidLength {
                expected: GENESIS_V1_LENGTH,
                actual: 43,
            })
        );
    }

    #[test]
    fn rejects_incorrect_magic_bytes() {
        let mut encoded = [0u8; GENESIS_V1_LENGTH];
        encoded[8..12].copy_from_slice(&GENESIS_VERSION.to_be_bytes());

        let result = GenesisConfig::decode(&encoded);

        assert_eq!(result, Err(GenesisError::InvalidMagic));
    }

    #[test]
    fn rejects_unsupported_encoded_version() {
        let network_id = NetworkId::new([3u8; NETWORK_ID_LENGTH]);
        let genesis = GenesisConfig::new(GENESIS_VERSION, network_id).unwrap(); 
                let mut encoded = genesis.encode().unwrap();
        encoded[8..12].copy_from_slice(&2u32.to_be_bytes());

        let result = GenesisConfig::decode(&encoded);

        assert_eq!(result, Err(GenesisError::UnsupportedVersion(2)));
    }
}
