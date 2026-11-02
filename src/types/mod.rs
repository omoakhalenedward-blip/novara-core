pub const HASH_LENGTH: usize = 32;
pub const ADDRESS_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32([u8; HASH_LENGTH]);

impl Hash32 {
    pub const fn from_bytes(bytes: [u8; HASH_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LENGTH] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(Hash32);

impl BlockId {
    pub const fn from_bytes(bytes: [u8; HASH_LENGTH]) -> Self {
        Self(Hash32::from_bytes(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LENGTH] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(Hash32);

impl TransactionId {
    pub const fn from_bytes(bytes: [u8; HASH_LENGTH]) -> Self {
        Self(Hash32::from_bytes(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LENGTH] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountAddress([u8; ADDRESS_LENGTH]);

impl AccountAddress {
    pub const fn from_bytes(bytes: [u8; ADDRESS_LENGTH]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ADDRESS_LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountAddress, BlockId, Hash32, TransactionId};

    #[test]
    fn constructors_preserve_bytes() {
        let bytes = [0xA5; 32];

        assert_eq!(Hash32::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(BlockId::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(TransactionId::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(AccountAddress::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn identifier_types_remain_distinct() {
        fn takes_block_id(_: BlockId) {}
        fn takes_transaction_id(_: TransactionId) {}
        fn takes_hash(_: Hash32) {}
        fn takes_address(_: AccountAddress) {}

        let bytes = [0; 32];
        takes_block_id(BlockId::from_bytes(bytes));
        takes_transaction_id(TransactionId::from_bytes(bytes));
        takes_hash(Hash32::from_bytes(bytes));
        takes_address(AccountAddress::from_bytes(bytes));
    }
}
