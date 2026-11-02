use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::types::{BlockId, TransactionId};

const HASH_PREFIX: &[u8] = b"NOVARA::HASH::V1\0";
const BLOCK_HEADER_DOMAIN: u8 = 0x01;
const TRANSACTION_DOMAIN: u8 = 0x02;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashError {
    InputLengthTooLarge { length: usize },
}

impl fmt::Display for HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLengthTooLarge { length } => {
                write!(formatter, "input length {length} does not fit in u64")
            }
        }
    }
}

impl Error for HashError {}

pub fn hash_block_header(canonical_header: &[u8]) -> Result<BlockId, HashError> {
    let digest = hash_canonical_bytes(BLOCK_HEADER_DOMAIN, canonical_header)?;
    Ok(BlockId::from_bytes(digest))
}

pub fn hash_transaction(canonical_transaction: &[u8]) -> Result<TransactionId, HashError> {
    let digest = hash_canonical_bytes(TRANSACTION_DOMAIN, canonical_transaction)?;
    Ok(TransactionId::from_bytes(digest))
}

fn hash_canonical_bytes(domain: u8, payload: &[u8]) -> Result<[u8; 32], HashError> {
    let length = u64::try_from(payload.len()).map_err(|_| HashError::InputLengthTooLarge {
        length: payload.len(),
    })?;

    let mut hasher = Sha256::new();
    hasher.update(HASH_PREFIX);
    hasher.update([domain]);
    hasher.update(length.to_be_bytes());
    hasher.update(payload);

    let digest = hasher.finalize();
    let mut output = [0; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{hash_block_header, hash_transaction};

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);

        for &byte in bytes {
            output.push(HEX[usize::from(byte >> 4)] as char);
            output.push(HEX[usize::from(byte & 0x0f)] as char);
        }

        output
    }

    #[test]
    fn block_header_test_vectors() {
        let empty = hash_block_header(b"").unwrap();
        let abc = hash_block_header(b"abc").unwrap();

        assert_eq!(
            hex(empty.as_bytes()),
            "d96353a86bbd7508aeaadea2878d64b59f49a73cbbf3917957ce3ec146f45ceb"
        );
        assert_eq!(
            hex(abc.as_bytes()),
            "a8bcd8b60d6fcc022e5d30097018a1a8fbdfa514f7369f5e9d6d40692f5977a7"
        );
    }

    #[test]
    fn transaction_test_vectors() {
        let empty = hash_transaction(b"").unwrap();
        let abc = hash_transaction(b"abc").unwrap();

        assert_eq!(
            hex(empty.as_bytes()),
            "c18182986067810f2f40317022507a0609f601da90880823b29fd7721cae3bba"
        );
        assert_eq!(
            hex(abc.as_bytes()),
            "2b06627bd0e6c40bdb486f2b9354166e1d7197c9e216de5d578217e0a15e1899"
        );
    }

    #[test]
    fn domains_produce_distinct_hashes_for_same_payload() {
        let payload = b"same canonical bytes";

        assert_ne!(
            hash_block_header(payload).unwrap().as_bytes(),
            hash_transaction(payload).unwrap().as_bytes()
        );
    }

    #[test]
    fn sha256_matches_standard_abc_vector() {
        let digest = Sha256::digest(b"abc");

        assert_eq!(
            hex(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
