use std::{collections::BTreeMap, error::Error, fmt, str};

use crate::{
    crypto::ed25519::{VerificationError, validate_ed25519_public_key, verify_ed25519},
    types::AccountAddress,
};

const TRANSACTION_MAGIC: &[u8; 8] = b"NOVATX1\0";
const TRANSACTION_VERSION: u16 = 1;
const CREATE_ACCOUNT_OPERATION: u8 = 0x01;
const ROTATE_KEY_OPERATION: u8 = 0x02;
const SIGNATURE_LENGTH: usize = 64;
const MAX_CHAIN_ID_LENGTH: usize = 50;
const MAX_TRANSACTION_LENGTH: usize = 1_024;
const MAX_VALIDITY_WINDOW: u64 = 100_000;
const MAX_COMETBFT_HEIGHT: u64 = i64::MAX as u64;
const CREATE_DOMAIN: &[u8] = b"NOVARA::AUTH::CREATE::V1\0";
const ROTATE_DOMAIN: &[u8] = b"NOVARA::AUTH::ROTATE::V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    id: AccountAddress,
    public_key: [u8; 32],
    next_nonce: u64,
}

impl Account {
    pub const fn id(&self) -> AccountAddress {
        self.id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub const fn next_nonce(&self) -> u64 {
        self.next_nonce
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountError {
    InvalidChainId,
    NetworkIdMismatch,
    ChainIdMismatch,
    InvalidNonce,
    InvalidValidityWindow,
    TransactionTooLarge,
    TransactionNotYetValid,
    TransactionExpired,
    AccountNotFound,
    DuplicateAccount,
    NonceExhausted,
    InvalidAccountState,
    Authentication(VerificationError),
}

impl fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChainId => formatter.write_str("chain ID must be 1–50 valid UTF-8 bytes"),
            Self::NetworkIdMismatch => formatter.write_str("transaction Network ID does not match"),
            Self::ChainIdMismatch => formatter.write_str("transaction Chain ID does not match"),
            Self::InvalidNonce => formatter.write_str("transaction nonce is not the next nonce"),
            Self::InvalidValidityWindow => {
                formatter.write_str("transaction validity window is invalid")
            }
            Self::TransactionTooLarge => {
                formatter.write_str("transaction exceeds the v1 size limit")
            }
            Self::TransactionNotYetValid => formatter.write_str("transaction is not yet valid"),
            Self::TransactionExpired => formatter.write_str("transaction has expired"),
            Self::AccountNotFound => formatter.write_str("account does not exist"),
            Self::DuplicateAccount => formatter.write_str("account ID already exists"),
            Self::NonceExhausted => formatter.write_str("account nonce cannot be incremented"),
            Self::InvalidAccountState => formatter.write_str("account state invariant is invalid"),
            Self::Authentication(error) => write!(formatter, "authentication failed: {error}"),
        }
    }
}

impl Error for AccountError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authentication(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountActionFailure {
    InvalidNewPublicKey(VerificationError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountActionResult {
    Applied,
    Failed(AccountActionFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateAccount {
    pub network_id: [u8; 32],
    pub chain_id: Vec<u8>,
    pub account_id: AccountAddress,
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expiry_height: u64,
    pub initial_public_key: [u8; 32],
    pub signature: [u8; SIGNATURE_LENGTH],
}

impl CreateAccount {
    pub fn signing_preimage(&self) -> Result<Vec<u8>, AccountError> {
        encode_signing_preimage(
            CREATE_DOMAIN,
            self.network_id,
            &self.chain_id,
            self.account_id,
            self.nonce,
            self.valid_from_height,
            self.expiry_height,
            CREATE_ACCOUNT_OPERATION,
            &self.initial_public_key,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotateAuthenticationKey {
    pub network_id: [u8; 32],
    pub chain_id: Vec<u8>,
    pub account_id: AccountAddress,
    pub nonce: u64,
    pub valid_from_height: u64,
    pub expiry_height: u64,
    pub new_public_key: [u8; 32],
    pub signature: [u8; SIGNATURE_LENGTH],
}

impl RotateAuthenticationKey {
    pub fn signing_preimage(&self) -> Result<Vec<u8>, AccountError> {
        encode_signing_preimage(
            ROTATE_DOMAIN,
            self.network_id,
            &self.chain_id,
            self.account_id,
            self.nonce,
            self.valid_from_height,
            self.expiry_height,
            ROTATE_KEY_OPERATION,
            &self.new_public_key,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    network_id: [u8; 32],
    chain_id: Vec<u8>,
    accounts: BTreeMap<AccountAddress, Account>,
}

impl AccountState {
    pub fn new(network_id: [u8; 32], chain_id: Vec<u8>) -> Result<Self, AccountError> {
        validate_chain_id(&chain_id)?;
        Ok(Self {
            network_id,
            chain_id,
            accounts: BTreeMap::new(),
        })
    }

    pub fn get(&self, account_id: &AccountAddress) -> Option<&Account> {
        self.accounts.get(account_id)
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Applies one included account-creation operation.
    ///
    /// Transaction parsing, inclusion, and ABCI integration remain the caller's responsibility.
    pub fn create_account(
        &mut self,
        request: &CreateAccount,
        execution_height: u64,
    ) -> Result<AccountActionResult, AccountError> {
        self.validate_request_context(
            request.network_id,
            &request.chain_id,
            request.valid_from_height,
            request.expiry_height,
            execution_height,
        )?;
        if request.nonce != 0 {
            return Err(AccountError::InvalidNonce);
        }

        let preimage = request.signing_preimage()?;
        verify_ed25519(&request.initial_public_key, &preimage, &request.signature)
            .map_err(AccountError::Authentication)?;

        if self.accounts.contains_key(&request.account_id) {
            return Err(AccountError::DuplicateAccount);
        }

        let account = Account {
            id: request.account_id,
            public_key: request.initial_public_key,
            next_nonce: 1,
        };
        self.accounts.insert(request.account_id, account);
        Ok(AccountActionResult::Applied)
    }

    /// Applies one included key-rotation operation in deterministic execution order.
    ///
    /// Transaction parsing, inclusion, and ABCI integration remain the caller's responsibility.
    pub fn rotate_key(
        &mut self,
        request: &RotateAuthenticationKey,
        execution_height: u64,
    ) -> Result<AccountActionResult, AccountError> {
        self.validate_request_context(
            request.network_id,
            &request.chain_id,
            request.valid_from_height,
            request.expiry_height,
            execution_height,
        )?;

        let account = self
            .accounts
            .get(&request.account_id)
            .copied()
            .ok_or(AccountError::AccountNotFound)?;
        if request.nonce != account.next_nonce {
            return Err(AccountError::InvalidNonce);
        }

        let preimage = request.signing_preimage()?;
        verify_ed25519(&account.public_key, &preimage, &request.signature)
            .map_err(AccountError::Authentication)?;
        let next_nonce = account
            .next_nonce
            .checked_add(1)
            .ok_or(AccountError::NonceExhausted)?;

        let outcome = match validate_ed25519_public_key(&request.new_public_key) {
            Ok(public_key) => {
                self.accounts.insert(
                    request.account_id,
                    Account {
                        id: account.id,
                        public_key,
                        next_nonce,
                    },
                );
                AccountActionResult::Applied
            }
            Err(error) => {
                self.accounts.insert(
                    request.account_id,
                    Account {
                        next_nonce,
                        ..account
                    },
                );
                AccountActionResult::Failed(AccountActionFailure::InvalidNewPublicKey(error))
            }
        };
        Ok(outcome)
    }

    pub fn validate(&self) -> Result<(), AccountError> {
        validate_chain_id(&self.chain_id)?;
        for (account_id, account) in &self.accounts {
            if account_id != &account.id
                || account.next_nonce == 0
                || validate_ed25519_public_key(&account.public_key).is_err()
            {
                return Err(AccountError::InvalidAccountState);
            }
        }
        Ok(())
    }

    fn validate_request_context(
        &self,
        network_id: [u8; 32],
        chain_id: &[u8],
        valid_from_height: u64,
        expiry_height: u64,
        execution_height: u64,
    ) -> Result<(), AccountError> {
        if network_id != self.network_id {
            return Err(AccountError::NetworkIdMismatch);
        }
        validate_chain_id(chain_id)?;
        if chain_id != self.chain_id {
            return Err(AccountError::ChainIdMismatch);
        }
        validate_validity_window(valid_from_height, expiry_height)?;
        if execution_height < valid_from_height {
            return Err(AccountError::TransactionNotYetValid);
        }
        if execution_height > expiry_height {
            return Err(AccountError::TransactionExpired);
        }
        Ok(())
    }
}

fn validate_chain_id(chain_id: &[u8]) -> Result<(), AccountError> {
    if chain_id.is_empty()
        || chain_id.len() > MAX_CHAIN_ID_LENGTH
        || str::from_utf8(chain_id).is_err()
    {
        return Err(AccountError::InvalidChainId);
    }
    Ok(())
}

fn validate_validity_window(valid_from: u64, expiry: u64) -> Result<(), AccountError> {
    if valid_from > MAX_COMETBFT_HEIGHT
        || expiry > MAX_COMETBFT_HEIGHT
        || expiry < valid_from
        || expiry - valid_from > MAX_VALIDITY_WINDOW
    {
        return Err(AccountError::InvalidValidityWindow);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_signing_preimage(
    domain: &[u8],
    network_id: [u8; 32],
    chain_id: &[u8],
    account_id: AccountAddress,
    nonce: u64,
    valid_from_height: u64,
    expiry_height: u64,
    operation: u8,
    operation_payload: &[u8; 32],
) -> Result<Vec<u8>, AccountError> {
    validate_chain_id(chain_id)?;
    validate_validity_window(valid_from_height, expiry_height)?;
    let chain_id_length =
        u16::try_from(chain_id.len()).map_err(|_| AccountError::InvalidChainId)?;
    let unsigned_transaction_length = TRANSACTION_MAGIC.len()
        + 2
        + network_id.len()
        + 2
        + chain_id.len()
        + account_id.as_bytes().len()
        + 8
        + 8
        + 8
        + 1
        + operation_payload.len();
    if unsigned_transaction_length + SIGNATURE_LENGTH > MAX_TRANSACTION_LENGTH {
        return Err(AccountError::TransactionTooLarge);
    }

    let mut preimage = Vec::with_capacity(domain.len() + unsigned_transaction_length);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(TRANSACTION_MAGIC);
    preimage.extend_from_slice(&TRANSACTION_VERSION.to_be_bytes());
    preimage.extend_from_slice(&network_id);
    preimage.extend_from_slice(&chain_id_length.to_be_bytes());
    preimage.extend_from_slice(chain_id);
    preimage.extend_from_slice(account_id.as_bytes());
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(&valid_from_height.to_be_bytes());
    preimage.extend_from_slice(&expiry_height.to_be_bytes());
    preimage.push(operation);
    preimage.extend_from_slice(operation_payload);
    Ok(preimage)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::{
        Account, AccountActionFailure, AccountActionResult, AccountError, AccountState,
        CREATE_ACCOUNT_OPERATION, CreateAccount, MAX_TRANSACTION_LENGTH, RotateAuthenticationKey,
    };
    use crate::{crypto::ed25519::VerificationError, types::AccountAddress};

    const NETWORK_ID: [u8; 32] = [0x11; 32];
    const CHAIN_ID: &[u8] = b"novara-test";
    const EXECUTION_HEIGHT: u64 = 5;

    fn account_id(byte: u8) -> AccountAddress {
        AccountAddress::from_bytes([byte; 32])
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn signed_create(id: AccountAddress, signing_key: &SigningKey) -> CreateAccount {
        let mut request = CreateAccount {
            network_id: NETWORK_ID,
            chain_id: CHAIN_ID.to_vec(),
            account_id: id,
            nonce: 0,
            valid_from_height: 1,
            expiry_height: 10,
            initial_public_key: signing_key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        request.signature = signing_key
            .sign(&request.signing_preimage().unwrap())
            .to_bytes();
        request
    }

    fn signed_rotation(
        id: AccountAddress,
        nonce: u64,
        signer: &SigningKey,
        new_key: [u8; 32],
    ) -> RotateAuthenticationKey {
        let mut request = RotateAuthenticationKey {
            network_id: NETWORK_ID,
            chain_id: CHAIN_ID.to_vec(),
            account_id: id,
            nonce,
            valid_from_height: 1,
            expiry_height: 10,
            new_public_key: new_key,
            signature: [0; 64],
        };
        request.signature = signer.sign(&request.signing_preimage().unwrap()).to_bytes();
        request
    }

    fn new_state() -> AccountState {
        AccountState::new(NETWORK_ID, CHAIN_ID.to_vec()).unwrap()
    }

    #[test]
    fn creates_and_retrieves_account_with_initial_next_nonce() {
        let signer = signing_key(1);
        let id = account_id(2);
        let mut state = new_state();

        assert_eq!(
            state.create_account(&signed_create(id, &signer), EXECUTION_HEIGHT),
            Ok(AccountActionResult::Applied)
        );
        let account = state.get(&id).unwrap();
        assert_eq!(account.id(), id);
        assert_eq!(account.public_key(), &signer.verifying_key().to_bytes());
        assert_eq!(account.next_nonce(), 1);
        assert_eq!(state.len(), 1);
        state.validate().unwrap();
    }

    #[test]
    fn duplicate_creation_does_not_replace_account_or_nonce() {
        let original_signer = signing_key(1);
        let duplicate_signer = signing_key(2);
        let id = account_id(3);
        let mut state = new_state();
        state
            .create_account(&signed_create(id, &original_signer), EXECUTION_HEIGHT)
            .unwrap();
        let original_account = *state.get(&id).unwrap();

        assert_eq!(
            state.create_account(&signed_create(id, &duplicate_signer), EXECUTION_HEIGHT),
            Err(AccountError::DuplicateAccount)
        );
        assert_eq!(state.get(&id), Some(&original_account));
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn invalid_authentication_leaves_all_account_state_unchanged() {
        let signer = signing_key(1);
        let id = account_id(4);
        let mut state = new_state();
        state
            .create_account(&signed_create(id, &signer), EXECUTION_HEIGHT)
            .unwrap();
        let before = state.clone();
        let mut request =
            signed_rotation(id, 1, &signer, signing_key(2).verifying_key().to_bytes());
        request.signature[0] ^= 1;

        assert!(matches!(
            state.rotate_key(&request, EXECUTION_HEIGHT),
            Err(AccountError::Authentication(_))
        ));
        assert_eq!(state, before);

        let before_invalid_create = state.clone();
        let mut invalid_create = signed_create(account_id(40), &signer);
        invalid_create.signature[0] ^= 1;
        assert!(matches!(
            state.create_account(&invalid_create, EXECUTION_HEIGHT),
            Err(AccountError::Authentication(_))
        ));
        assert_eq!(state, before_invalid_create);
    }

    #[test]
    fn rotation_requires_current_key_and_consumes_nonce_atomically() {
        let current_key = signing_key(1);
        let replacement_key = signing_key(2);
        let stale_key = signing_key(3);
        let id = account_id(5);
        let mut state = new_state();
        state
            .create_account(&signed_create(id, &current_key), EXECUTION_HEIGHT)
            .unwrap();

        let before_wrong_domain = state.clone();
        let mut wrong_domain = signed_rotation(
            id,
            1,
            &current_key,
            replacement_key.verifying_key().to_bytes(),
        );
        wrong_domain.signature = signed_create(id, &current_key).signature;
        assert!(matches!(
            state.rotate_key(&wrong_domain, EXECUTION_HEIGHT),
            Err(AccountError::Authentication(_))
        ));
        assert_eq!(state, before_wrong_domain);

        assert_eq!(
            state.rotate_key(
                &signed_rotation(
                    id,
                    1,
                    &current_key,
                    replacement_key.verifying_key().to_bytes()
                ),
                EXECUTION_HEIGHT
            ),
            Ok(AccountActionResult::Applied)
        );
        let rotated = state.get(&id).unwrap();
        assert_eq!(rotated.id(), id);
        assert_eq!(
            rotated.public_key(),
            &replacement_key.verifying_key().to_bytes()
        );
        assert_eq!(rotated.next_nonce(), 2);

        let before_replay = state.clone();
        assert!(matches!(
            state.rotate_key(
                &signed_rotation(id, 1, &current_key, stale_key.verifying_key().to_bytes()),
                EXECUTION_HEIGHT
            ),
            Err(AccountError::InvalidNonce)
        ));
        assert_eq!(state, before_replay);
        assert!(matches!(
            state.rotate_key(
                &signed_rotation(id, 2, &stale_key, current_key.verifying_key().to_bytes()),
                EXECUTION_HEIGHT
            ),
            Err(AccountError::Authentication(_))
        ));
        assert_eq!(state, before_replay);
    }

    #[test]
    fn authenticated_failed_rotation_consumes_nonce_without_changing_key() {
        let signer = signing_key(1);
        let id = account_id(6);
        let mut state = new_state();
        state
            .create_account(&signed_create(id, &signer), EXECUTION_HEIGHT)
            .unwrap();
        let original_key = *state.get(&id).unwrap().public_key();
        let invalid_new_key = [0; 32];

        assert_eq!(
            state.rotate_key(
                &signed_rotation(id, 1, &signer, invalid_new_key),
                EXECUTION_HEIGHT
            ),
            Ok(AccountActionResult::Failed(
                AccountActionFailure::InvalidNewPublicKey(VerificationError::SmallOrderPoint {
                    role: crate::crypto::ed25519::PointRole::PublicKey
                })
            ))
        );
        let account = state.get(&id).unwrap();
        assert_eq!(account.public_key(), &original_key);
        assert_eq!(account.next_nonce(), 2);
    }

    #[test]
    fn invalid_network_chain_nonce_and_height_do_not_mutate_state() {
        let signer = signing_key(1);
        let id = account_id(7);
        let mut state = new_state();
        state
            .create_account(&signed_create(id, &signer), EXECUTION_HEIGHT)
            .unwrap();
        let before = state.clone();

        let mut request =
            signed_rotation(id, 1, &signer, signing_key(2).verifying_key().to_bytes());
        request.network_id[0] ^= 1;
        assert_eq!(
            state.rotate_key(&request, EXECUTION_HEIGHT),
            Err(AccountError::NetworkIdMismatch)
        );

        request.network_id = NETWORK_ID;
        request.chain_id = b"other-chain".to_vec();
        assert_eq!(
            state.rotate_key(&request, EXECUTION_HEIGHT),
            Err(AccountError::ChainIdMismatch)
        );

        request.chain_id = CHAIN_ID.to_vec();
        request.nonce = 2;
        assert_eq!(
            state.rotate_key(&request, EXECUTION_HEIGHT),
            Err(AccountError::InvalidNonce)
        );

        request.nonce = 1;
        request.valid_from_height = 6;
        assert_eq!(
            state.rotate_key(&request, EXECUTION_HEIGHT),
            Err(AccountError::TransactionNotYetValid)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn invalid_state_is_detected_and_account_has_no_private_key_field() {
        let signer = signing_key(1);
        let id = account_id(8);
        let mut state = new_state();
        state
            .create_account(&signed_create(id, &signer), EXECUTION_HEIGHT)
            .unwrap();
        state.validate().unwrap();

        let account = Account {
            id,
            public_key: [0; 32],
            next_nonce: 1,
        };
        state.accounts.insert(id, account);
        assert_eq!(state.validate(), Err(AccountError::InvalidAccountState));
    }

    #[test]
    fn nonce_overflow_is_rejected_without_wrapping_or_mutation() {
        let signer = signing_key(1);
        let id = account_id(9);
        let mut state = new_state();
        state
            .create_account(&signed_create(id, &signer), EXECUTION_HEIGHT)
            .unwrap();
        let account = state.accounts.get_mut(&id).unwrap();
        account.next_nonce = u64::MAX;
        let before = state.clone();
        let request = signed_rotation(
            id,
            u64::MAX,
            &signer,
            signing_key(2).verifying_key().to_bytes(),
        );

        assert_eq!(
            state.rotate_key(&request, EXECUTION_HEIGHT),
            Err(AccountError::NonceExhausted)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn identical_ordered_operations_produce_identical_account_state() {
        let signer = signing_key(1);
        let replacement = signing_key(2);
        let id = account_id(10);
        let create = signed_create(id, &signer);
        let rotation = signed_rotation(id, 1, &signer, replacement.verifying_key().to_bytes());
        let mut first = new_state();
        let mut second = new_state();

        first.create_account(&create, EXECUTION_HEIGHT).unwrap();
        first.rotate_key(&rotation, EXECUTION_HEIGHT).unwrap();
        second.create_account(&create, EXECUTION_HEIGHT).unwrap();
        second.rotate_key(&rotation, EXECUTION_HEIGHT).unwrap();

        assert_eq!(first, second);
        first.validate().unwrap();
        second.validate().unwrap();
    }

    #[test]
    fn signing_preimage_uses_fixed_canonical_field_order() {
        let signer = signing_key(1);
        let request = signed_create(account_id(2), &signer);
        let preimage = request.signing_preimage().unwrap();
        let domain = b"NOVARA::AUTH::CREATE::V1\0";
        assert!(preimage.starts_with(domain));
        let unsigned = &preimage[domain.len()..];
        assert_eq!(&unsigned[..8], b"NOVATX1\0");
        assert_eq!(u16::from_be_bytes([unsigned[8], unsigned[9]]), 1);
        assert_eq!(&unsigned[10..42], &NETWORK_ID);
        assert_eq!(
            u16::from_be_bytes([unsigned[42], unsigned[43]]),
            CHAIN_ID.len() as u16
        );
        assert_eq!(&unsigned[44..44 + CHAIN_ID.len()], CHAIN_ID);
        let account_id_offset = 44 + CHAIN_ID.len();
        assert_eq!(
            &unsigned[account_id_offset..account_id_offset + 32],
            account_id(2).as_bytes()
        );
        assert_eq!(
            u64::from_be_bytes(
                unsigned[account_id_offset + 32..account_id_offset + 40]
                    .try_into()
                    .unwrap()
            ),
            0
        );
        assert_eq!(unsigned[account_id_offset + 56], CREATE_ACCOUNT_OPERATION);
        assert_eq!(
            &unsigned[account_id_offset + 57..account_id_offset + 89],
            &request.initial_public_key
        );
        assert!(unsigned.len() + 64 <= MAX_TRANSACTION_LENGTH);
        assert!(
            signed_rotation(request.account_id, 0, &signer, request.initial_public_key)
                .signing_preimage()
                .unwrap()
                .starts_with(b"NOVARA::AUTH::ROTATE::V1\0")
        );
        assert_ne!(
            preimage,
            signed_rotation(request.account_id, 0, &signer, request.initial_public_key)
                .signing_preimage()
                .unwrap()
        );
    }
}
