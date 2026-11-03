use std::str;

pub const TRANSACTION_MAGIC: &[u8; 8] = b"NOVATX1\0";
pub const FORMAT_VERSION: u16 = 1;
pub const SIGNATURE_LENGTH: usize = 64;
pub const MAX_CHAIN_ID_LENGTH: usize = 50;
pub const MAX_TRANSACTION_LENGTH: usize = 1_024;
pub const MAX_VALIDITY_WINDOW: u64 = 100_000;
pub const MAX_COMETBFT_HEIGHT: u64 = i64::MAX as u64;

const CREATE_ACCOUNT_OPERATION: u8 = 0x01;
const ROTATE_KEY_OPERATION: u8 = 0x02;
const NETWORK_ID_LENGTH: usize = 32;
const ACCOUNT_ID_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    CreateAccount {
        public_key: [u8; PUBLIC_KEY_LENGTH],
    },
    RotateAuthenticationKey {
        new_public_key: [u8; PUBLIC_KEY_LENGTH],
    },
}

impl Operation {
    pub const fn code(self) -> u8 {
        match self {
            Self::CreateAccount { .. } => CREATE_ACCOUNT_OPERATION,
            Self::RotateAuthenticationKey { .. } => ROTATE_KEY_OPERATION,
        }
    }

    const fn public_key(self) -> [u8; PUBLIC_KEY_LENGTH] {
        match self {
            Self::CreateAccount { public_key } => public_key,
            Self::RotateAuthenticationKey { new_public_key } => new_public_key,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: u16,
    pub network_id: [u8; NETWORK_ID_LENGTH],
    pub chain_id: Vec<u8>,
    pub account_id: [u8; ACCOUNT_ID_LENGTH],
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expiry_height: u64,
    pub operation: Operation,
    pub signature: [u8; SIGNATURE_LENGTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    TransactionTooLarge,
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidChainId,
    InvalidValidityWindow,
    InvalidOperation(u8),
    TrailingBytes,
    LengthOverflow,
}

impl Transaction {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;

        let mut encoded = self.encode_unsigned()?;
        checked_total_length(encoded.len(), self.signature.len())?;
        encoded.extend_from_slice(&self.signature);
        Ok(encoded)
    }

    pub fn encode_unsigned(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;

        let length = unsigned_length(self.chain_id.len())?;
        if checked_total_length(length, self.signature.len())? > MAX_TRANSACTION_LENGTH {
            return Err(FormatError::TransactionTooLarge);
        }

        let mut encoded = Vec::with_capacity(length);
        encoded.extend_from_slice(TRANSACTION_MAGIC);
        encoded.extend_from_slice(&self.version.to_be_bytes());
        encoded.extend_from_slice(&self.network_id);
        encoded.extend_from_slice(
            &u16::try_from(self.chain_id.len())
                .map_err(|_| FormatError::InvalidChainId)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&self.chain_id);
        encoded.extend_from_slice(&self.account_id);
        encoded.extend_from_slice(&self.nonce.to_be_bytes());
        encoded.extend_from_slice(&self.valid_from_height.to_be_bytes());
        encoded.extend_from_slice(&self.expiry_height.to_be_bytes());
        encoded.push(self.operation.code());
        encoded.extend_from_slice(&self.operation.public_key());
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_TRANSACTION_LENGTH {
            return Err(FormatError::TransactionTooLarge);
        }

        let mut reader = Reader::new(bytes);
        if reader.take(TRANSACTION_MAGIC.len())? != TRANSACTION_MAGIC {
            return Err(FormatError::InvalidMagic);
        }

        let version = reader.u16()?;
        if version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }

        let network_id = reader.array()?;
        let chain_id_length = usize::from(reader.u16()?);
        if !(1..=MAX_CHAIN_ID_LENGTH).contains(&chain_id_length) {
            return Err(FormatError::InvalidChainId);
        }
        let chain_id = reader.take(chain_id_length)?.to_vec();
        validate_chain_id(&chain_id)?;

        let account_id = reader.array()?;
        let nonce = reader.u64()?;
        let valid_from_height = reader.u64()?;
        let expiry_height = reader.u64()?;
        validate_validity_window(valid_from_height, expiry_height)?;

        let code = reader.u8()?;
        let public_key = reader.array()?;
        let operation = match code {
            CREATE_ACCOUNT_OPERATION => Operation::CreateAccount { public_key },
            ROTATE_KEY_OPERATION => Operation::RotateAuthenticationKey {
                new_public_key: public_key,
            },
            other => return Err(FormatError::InvalidOperation(other)),
        };
        let signature = reader.array()?;
        if !reader.is_finished() {
            return Err(FormatError::TrailingBytes);
        }

        Ok(Self {
            version,
            network_id,
            chain_id,
            account_id,
            nonce,
            valid_from_height,
            expiry_height,
            operation,
            signature,
        })
    }

    fn validate(&self) -> Result<(), FormatError> {
        if self.version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(self.version));
        }
        validate_chain_id(&self.chain_id)?;
        validate_validity_window(self.valid_from_height, self.expiry_height)?;
        let total_length =
            checked_total_length(unsigned_length(self.chain_id.len())?, self.signature.len())?;
        if total_length > MAX_TRANSACTION_LENGTH {
            return Err(FormatError::TransactionTooLarge);
        }
        Ok(())
    }
}

fn validate_chain_id(chain_id: &[u8]) -> Result<(), FormatError> {
    if chain_id.is_empty()
        || chain_id.len() > MAX_CHAIN_ID_LENGTH
        || str::from_utf8(chain_id).is_err()
    {
        return Err(FormatError::InvalidChainId);
    }
    Ok(())
}

fn validate_validity_window(valid_from: u64, expiry: u64) -> Result<(), FormatError> {
    if valid_from > MAX_COMETBFT_HEIGHT
        || expiry > MAX_COMETBFT_HEIGHT
        || expiry < valid_from
        || expiry - valid_from > MAX_VALIDITY_WINDOW
    {
        return Err(FormatError::InvalidValidityWindow);
    }
    Ok(())
}

fn unsigned_length(chain_id_length: usize) -> Result<usize, FormatError> {
    [
        TRANSACTION_MAGIC.len(),
        2,
        NETWORK_ID_LENGTH,
        2,
        chain_id_length,
        ACCOUNT_ID_LENGTH,
        8,
        8,
        8,
        1,
        PUBLIC_KEY_LENGTH,
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or(FormatError::LengthOverflow)
}

fn checked_total_length(
    unsigned_length: usize,
    signature_length: usize,
) -> Result<usize, FormatError> {
    unsigned_length
        .checked_add(signature_length)
        .ok_or(FormatError::LengthOverflow)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], FormatError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FormatError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FormatError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        self.take(N)?.try_into().map_err(|_| FormatError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FORMAT_VERSION, FormatError, MAX_CHAIN_ID_LENGTH, MAX_TRANSACTION_LENGTH, Operation,
        TRANSACTION_MAGIC, Transaction,
    };

    fn transaction(operation: Operation) -> Transaction {
        Transaction {
            version: FORMAT_VERSION,
            network_id: [0x11; 32],
            chain_id: b"novara-test".to_vec(),
            account_id: [0x22; 32],
            nonce: 0x0102_0304_0506_0708,
            valid_from_height: 5,
            expiry_height: 15,
            operation,
            signature: [0x33; 64],
        }
    }

    #[test]
    fn encodes_and_decodes_creation_transaction() {
        let tx = transaction(Operation::CreateAccount {
            public_key: [0x44; 32],
        });
        let encoded = tx.encode().unwrap();

        assert_eq!(&encoded[..8], TRANSACTION_MAGIC);
        assert_eq!(&encoded[8..10], &[0, 1]);
        assert_eq!(encoded[10..42], [0x11; 32]);
        assert_eq!(&encoded[42..44], &[0, 11]);
        assert_eq!(&encoded[44..55], b"novara-test");
        assert_eq!(encoded[55..87], [0x22; 32]);
        assert_eq!(&encoded[87..95], &tx.nonce.to_be_bytes());
        assert_eq!(&encoded[95..103], &tx.valid_from_height.to_be_bytes());
        assert_eq!(&encoded[103..111], &tx.expiry_height.to_be_bytes());
        assert_eq!(encoded[111], 0x01);
        assert_eq!(Transaction::decode(&encoded), Ok(tx));
    }

    #[test]
    fn encodes_and_decodes_key_rotation_transaction() {
        let tx = transaction(Operation::RotateAuthenticationKey {
            new_public_key: [0x55; 32],
        });
        let encoded = tx.encode().unwrap();

        assert_eq!(encoded[111], 0x02);
        assert_eq!(encoded[112..144], [0x55; 32]);
        assert_eq!(encoded[144..], [0x33; 64]);
        assert_eq!(Transaction::decode(&encoded), Ok(tx));
    }

    #[test]
    fn enforces_chain_id_byte_length_and_utf8() {
        let mut tx = transaction(Operation::CreateAccount {
            public_key: [0x44; 32],
        });
        tx.chain_id = vec![b'a'; MAX_CHAIN_ID_LENGTH];
        assert!(tx.encode().is_ok());

        tx.chain_id.push(b'a');
        assert_eq!(tx.encode(), Err(FormatError::InvalidChainId));
        tx.chain_id = vec![0xff];
        assert_eq!(tx.encode(), Err(FormatError::InvalidChainId));
        tx.chain_id.clear();
        assert_eq!(tx.encode(), Err(FormatError::InvalidChainId));
    }

    #[test]
    fn rejects_unsupported_version_invalid_operation_and_bad_magic() {
        let tx = transaction(Operation::CreateAccount {
            public_key: [0x44; 32],
        });
        let mut encoded = tx.encode().unwrap();

        encoded[9] = 2;
        assert_eq!(
            Transaction::decode(&encoded),
            Err(FormatError::UnsupportedVersion(2))
        );

        encoded = tx.encode().unwrap();
        encoded[111] = 3;
        assert_eq!(
            Transaction::decode(&encoded),
            Err(FormatError::InvalidOperation(3))
        );

        encoded = tx.encode().unwrap();
        encoded[0] ^= 1;
        assert_eq!(
            Transaction::decode(&encoded),
            Err(FormatError::InvalidMagic)
        );
    }

    #[test]
    fn rejects_truncated_and_trailing_bytes() {
        let tx = transaction(Operation::CreateAccount {
            public_key: [0x44; 32],
        });
        let encoded = tx.encode().unwrap();

        assert_eq!(
            Transaction::decode(&encoded[..encoded.len() - 1]),
            Err(FormatError::Truncated)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            Transaction::decode(&trailing),
            Err(FormatError::TrailingBytes)
        );
    }

    #[test]
    fn rejects_invalid_validity_window_and_oversized_input() {
        let mut tx = transaction(Operation::CreateAccount {
            public_key: [0x44; 32],
        });
        tx.expiry_height = tx.valid_from_height - 1;
        assert_eq!(tx.encode(), Err(FormatError::InvalidValidityWindow));

        assert_eq!(
            Transaction::decode(&vec![0; MAX_TRANSACTION_LENGTH + 1]),
            Err(FormatError::TransactionTooLarge)
        );
    }
}
