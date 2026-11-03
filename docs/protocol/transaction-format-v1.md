# NOVARA Transaction Format v1 — Draft

- **Status:** Draft; account-authentication and signing rules below are approved and normative, but v1 transaction execution is not implemented or production-ready
- **Date:** 2026-11-02
- **Scope:** Canonical transaction envelope, account creation, key rotation, authentication, and replay protection

This document records approved normative v1 account-authentication and signing rules alongside remaining draft transaction details. Items marked **UNRESOLVED** are not defined by this specification and must not be inferred by implementations. Nothing in this document changes the CometBFT block format or its transaction hash.

## 1. Design goals and terms

- A transaction has exactly one canonical byte representation.
- Every validator parses and executes the same bytes in block order and reaches the same result from the same pre-state.
- The signed message binds the NOVARA Network ID and CometBFT Chain ID, account, nonce, operation, version, and validity window.
- A NOVARA transaction ID is distinct from CometBFT's hash of the raw transaction bytes.
- Account IDs are client-generated opaque 32-byte values, independent of authentication keys.
- The approved NOVARA Network ID is distinct from the CometBFT Chain ID; both identify the signing context.

**APPROVED — NORMATIVE:** All multibyte integers in v1 are unsigned big-endian unless a field explicitly says otherwise. There are no optional fields, padding bytes, implicit defaults, or alternate encodings in version 1.

## 2. Network identity

**APPROVED DECISION:** Each NOVARA network has one Network ID, exactly 32 bytes. It is generated once when the network is created using a cryptographically secure random-number generator and stored in the application's genesis state. CometBFT delivers the genesis application state to the application through `InitChain`; validators must parse it and reject initialization unless the Network ID is exactly 32 bytes. Once initialized, the Network ID is immutable for that network's lifetime.

Every transaction includes the Network ID, and the signing preimage binds it alongside the CometBFT Chain ID. Validators reject transactions if either identifier differs from the identifiers initialized for their network. Wallets must verify the Network ID against trusted network configuration before signing; they must not treat an untrusted RPC-provided value as sufficient verification.

A fork intended to become an independent network must be assigned a new Network ID. Copying a genesis file copies its Network ID, so a copied network will share the original network's transaction replay domain unless its genesis configuration is deliberately changed before launch. The random generation procedure reduces accidental collisions between independently created networks but cannot distinguish copied genesis or make a fork independent automatically.

**IMPLEMENTATION DETAILS STILL TO SPECIFY:** The exact application-genesis schema and encoding, operational procedure for securely generating and distributing the ID, and how forks coordinate assignment of a new ID. These details must preserve the approved 32-byte, genesis-stored, immutable identity and must not delegate generation to individual validators.

## 3. Chain identifier

**APPROVED — NORMATIVE:** The NOVARA transaction Chain ID is the UTF-8 byte sequence of the CometBFT `chain_id` string, byte-for-byte, with no case folding, Unicode normalization, prefix, or separate NOVARA alias. The application obtains the configured value from CometBFT's `InitChain` request and requires every transaction's Chain ID to equal it exactly.

For CometBFT v0.40.0, the genesis chain ID is a string with a maximum length of 50 bytes. The v1 field allows 1 through 50 UTF-8 bytes. The bound is measured in bytes, not Unicode scalar values. Validators reject invalid UTF-8, an empty chain ID, an oversized value, or a byte sequence not exactly equal to the configured chain ID. Validators must not normalize identifiers.

The Network ID is an additional application-level replay boundary; the Chain ID remains separately bound and checked. Networks that reuse a Chain ID can still be distinguished if their Network IDs differ. Reusing or copying both identifiers preserves the same transaction signing domain.

## 4. Wire envelope and field order

**APPROVED — NORMATIVE:** `u8`, `u16`, `u32`, and `u64` denote unsigned integers of exactly that width. `bytes[N]` is exactly N octets. `bytes_u16` is a `u16` unsigned big-endian byte length followed by exactly that many octets. Length prefixes count bytes, not characters.

The canonical transaction is the following concatenation, in this exact order:

| Offset/order | Field | Encoding |
|---|---|---|
| 1 | Magic | 8 bytes: ASCII `NOVATX1` followed by `0x00` |
| 2 | Format version | `u16`, exactly `1` |
| 3 | NOVARA Network ID | `bytes[32]` |
| 4 | CometBFT Chain ID | `bytes_u16`, UTF-8, 1–50 bytes |
| 5 | Account ID | `bytes[32]` |
| 6 | Account nonce | `u64` |
| 7 | Valid-from height | `u64` |
| 8 | Expiry height | `u64` |
| 9 | Operation code | `u8` |
| 10 | Operation payload | Exact payload for the operation code; no payload length or trailing fields |
| 11 | Signature | `bytes[64]` |

The signature is the final field, so its fixed size is known once the payload has been parsed. The format has no transaction-level extension map: adding fields or changing their meaning requires a new format version. Unknown versions and operation codes are rejected. The maximum complete transaction size is 1,024 bytes.

**APPROVED — NORMATIVE validity rule:** `valid_from_height <= execution_block_height <= expiry_height`; both bounds are inclusive. Require `expiry_height >= valid_from_height`, and limit the window to at most 100,000 height increments (`expiry_height - valid_from_height <= 100,000`). Heights must be no greater than `i64::MAX`, matching CometBFT's signed block-height range. Use the CometBFT height of the block being executed, never local time. `CheckTx` may perform preliminary checks, but block execution must recheck the window against the execution height.

## 5. Operations and payloads

Operation codes are single octets. Other values are invalid in version 1.

### `0x01` — Create account

Payload, in order:

| Field | Encoding |
|---|---|
| Initial authentication public key | `bytes[32]` |

The account ID in the envelope is supplied by the client and must have been generated using a cryptographically secure random-number generator. It is included in the signed message. Validators never generate, replace, or derive an ID from the key.

The creation signature is checked against the proposed initial public key. If valid, creation succeeds only if the submitted account ID is absent from state at that point in sequential block execution. A duplicate ID must not overwrite, authenticate as, or change the existing account.

**APPROVED — NORMATIVE:** Account creation uses nonce 0. After successful creation, the account's next expected nonce is 1. A duplicate creation is rejected and must not overwrite or alter the existing account, key, or nonce. Because the creation signature does not authorize the existing account, a duplicate creation never consumes that account's nonce. The duplicate creation's deterministic transaction result is failure.

### `0x02` — Rotate authentication key

Payload, in order:

| Field | Encoding |
|---|---|
| New authentication public key | `bytes[32]` |

The account must already exist. The signature is verified against the currently registered key and the envelope's current expected nonce before any state change. On success, atomically replace the registered key and consume exactly that nonce. The account ID remains unchanged. A replayed rotation, stale nonce, or signature from a key no longer registered is rejected; it must not alter key or nonce state.

**APPROVED — NORMATIVE:** For an existing account, the transaction nonce equals its next expected nonce, initially 1 after account creation. A transaction included in a block that authenticates under the currently registered key and expected nonce consumes that nonce even if its requested operation fails. Invalid authentication, including a bad signature, wrong network/chain/account, invalid validity window, missing account, or replayed/out-of-sequence nonce, consumes no nonce and changes no account state. Nonce increment uses checked arithmetic; a transaction at `u64::MAX` cannot wrap and is rejected without mutation. No fee or gas behavior is defined here.

An authenticated rotation whose requested new key is invalid consumes its nonce, leaves the current key unchanged, and returns a deterministic failed-action result. Duplicate account creation is the explicit exception: it does not consume any nonce belonging to the existing account.

## 6. Signing message

Version 1 uses **pure Ed25519** over a canonical signing preimage. Ed25519ctx and Ed25519ph are different algorithms for this purpose and are not interchangeable with v1.

**APPROVED — NORMATIVE signing preimage:** Pure Ed25519 signs the exact byte concatenation below. Each operation has its own versioned domain separator:

```text
create_preimage =
    ASCII("NOVARA::AUTH::CREATE::V1\0")
    || canonical_transaction_unsigned

rotate_preimage =
    ASCII("NOVARA::AUTH::ROTATE::V1\0")
    || canonical_transaction_unsigned
```

`canonical_transaction_unsigned` is the exact concatenation of envelope fields 1–10, from Magic through Operation payload, excluding Signature. Integers use the fixed big-endian widths in section 4; Chain ID uses the exact UTF-8 bytes with its `u16` big-endian byte length. No fields are omitted or reordered. Thus the signature commits to:

- format version and operation code;
- exact NOVARA Network ID bytes and exact CometBFT Chain ID bytes;
- account ID and nonce;
- valid-from and expiry heights;
- every operation payload field, including the initial or replacement public key.

Account creation and key rotation use distinct domain separators as well as distinct operation codes. Any future operation requires its own operation-specific domain separator and code under a new approved specification/version; it must not reuse either v1 domain.

No signing implementation may sign a display form, decoded object, or reserialized object that differs from these canonical bytes.

The signing preimage binds both the NOVARA Network ID and CometBFT Chain ID. Transaction metadata outside the envelope is not signed and must not affect v1 execution.

## 7. Transaction ID

NOVARA's transaction ID is not CometBFT's raw transaction hash.

**PROPOSED v1 calculation:**

```text
tx_id = SHA-256(
    ASCII("NOVARA::TXID::V1\0")
    || canonical_transaction
)
```

`canonical_transaction` includes the signature. The digest is the 32-byte NOVARA transaction ID. CometBFT continues to hash and prove inclusion of the exact raw transaction bytes according to its own rules; no claim is made that the two hashes are equal.

**UNRESOLVED:** Approval of the domain literal, whether a transaction ID should include the signature, and whether the existing `hash_transaction` helper is suitable. The helper must not be assumed to implement this proposal unless its exact preimage is shown to match.

## 8. Ed25519 verification and key encoding

**APPROVED — NORMATIVE: NOVARA STRICT ED25519 POLICY.** Public keys are exactly 32 bytes and signatures exactly 64 bytes; reject other lengths before parsing or cryptographic work. A signature is 32-byte compressed point `R` followed by 32-byte scalar `S`. A compressed Edwards-Y point encoding uses the low 255 bits as the little-endian integer `y` and the high bit as the sign of `x`. For both public-key point `A` and signature point `R`, require `y < 2^255 - 19`, successful point decompression, rejection of `x = 0` with sign bit 1, and byte-for-byte equality when the decoded point is re-encoded. Both points must belong to the prime-order subgroup and must not be small-order, including the identity point. `S` must be a canonical little-endian scalar satisfying `0 <= S < L`, where `L` is the Ed25519 subgroup order. Use pure Ed25519, not Ed25519ctx or Ed25519ph, and verify with strict semantics. Malformed or invalid authentication must never mutate application state or consume a nonce. All validators must implement exactly the same acceptance rules.

**IMPLEMENTED DEPENDENCIES:** `ed25519-dalek` 2.2.0 and direct `curve25519-dalek` 4.1.3 dependencies are pinned exactly with default features disabled. The dedicated `crypto::ed25519` verifier enforces the normative `y` and sign-bit rules, then uses `VerifyingKey::from_bytes` and `verify_strict`, plus `CompressedEdwardsY`/`EdwardsPoint` operations to independently decompress `A` and `R`, round-trip their canonical encodings, and check `is_torsion_free()` and `!is_small_order()` for both points. The direct curve dependency is the application's API contract; a transitive dependency alone is not sufficient.

`ed25519-dalek` documents ZIP-215 decoding in `VerifyingKey::from_bytes`; that constructor does not implement all NOVARA requirements. `verify_strict()` checks canonical scalar form and rejects small-order public keys and `R`, but it does not alone enforce the normative `y` bound, sign-bit rule, byte-canonical encodings, or prime-order subgroup membership for both points. Therefore, explicit checks are mandatory. The `legacy_compatibility` feature relaxes scalar validation and must not be enabled in any consensus build. Ordinary `verify()` must not replace strict verification. Batch verification must not be introduced unless conformance tests prove its complete acceptance/rejection behavior equivalent to the approved individual strict path.

NOVARA's policy is its own strict profile, not ZIP-215. The library's documentation describes `verify_strict()` as technically non-RFC-8032-compliant because it intentionally rejects additional malleable cases. Library names or defaults do not replace the normative NOVARA rules.

**UNRESOLVED IMPLEMENTATION DETAILS:** Consensus feature-graph enforcement in every build configuration, application integration, and independent implementation comparison remain to be specified and reviewed. The exact dependency pins and normative point encoding and acceptance rules are implemented above; implementations must not widen or narrow the validator acceptance set.

## 9. V1 limits and malformed input

The following v1 limits and rejection rules are **APPROVED — NORMATIVE**:

| Item | Approved v1 limit |
|---|---:|
| Total canonical transaction size | 1,024 bytes maximum |
| Chain ID | 1–50 UTF-8 bytes |
| Validity window | At most 100,000 height increments; inclusive endpoints |
| Unknown format version or operation code | Reject |

Reject malformed input before state access where possible: wrong magic, unsupported version, missing or incorrectly sized Network ID, truncated length or field, invalid or oversized chain ID, noncanonical field encoding, unknown operation, payload of the wrong exact size, missing or extra bytes, invalid validity interval, or malformed key/signature encoding. Never truncate, normalize, pad, or silently default fields. Reject a well-formed transaction if either its Network ID or Chain ID differs from the initialized network identifiers.

The Network ID's exact 32-byte size is an approved protocol requirement, not a proposed resource limit.

Validation order must be deterministic and must not mutate committed state during parsing or authentication. For authenticated action failures, apply only the nonce behavior specified above; do not infer fee or other state effects from this document.

CometBFT or application block limits may be lower; that does not expand the v1 transaction maximum.

## 10. Deterministic validation outline

For each transaction in block order, validators:

1. Parse the exact envelope and reject malformed/noncanonical bytes.
2. Require the format version, exact initialized Network ID and Chain ID, operation, and height window to be valid.
3. Resolve the account according to the operation: create uses the proposed key and requires the submitted ID to be absent; rotation requires an existing account and its registered key.
4. Check operation-specific nonce rules and strict Ed25519 verification over the canonical signing preimage.
5. Apply the operation and nonce transition atomically according to the approved failure rules.

No validator independently generates IDs, reads local wall time, samples randomness, or uses environment-specific policy during these steps.

## 11. Required conformance vectors and tests

Before implementation is considered interoperable, publish fixed vectors containing the exact input fields, canonical unsigned bytes, signing preimage, public key, signature, complete transaction bytes, transaction ID, expected validation result, and resulting account/nonce state.

Vectors and tests must cover:

- both operation payload layouts and exact field order, including the 32-byte Network ID before the Chain ID;
- Network ID length rejection, exact configured-ID matching, transaction signatures that differ when either identifier changes, and rejection of the same transaction under another Network ID;
- wallet signing only after comparison with trusted network configuration; independent-network genesis files with distinct IDs; and copied genesis files retaining the same ID;
- a fork assigned a new ID rejecting transactions signed for its parent Network ID, and an explicitly documented same-ID fork sharing the same replay domain;
- big-endian integer and length-prefix boundaries, empty/maximum chain IDs, and validity-window endpoints;
- account creation success, duplicate ID rejection (including duplicate IDs earlier in the same block), and unchanged existing state on collision;
- key rotation signed by the current key, replay, stale key, wrong account, wrong chain, wrong nonce, and atomic key/nonce transition;
- valid signature vectors and altered message, key, and signature cases;
- wrong public-key/signature lengths; canonical and noncanonical `A`/`R` encodings; `y = 2^255 - 19` and values above that bound; failed decompressions; `x = 0` with sign bit 0 and 1; exact decode/re-encode equality; every low-order point including identity; mixed-torsion points; and prime-subgroup versus torsion-bearing cases for both `A` and `R`;
- canonical `S = L-1` acceptance and `S = L`, `L+1`, and other noncanonical/high scalar rejection; a consensus build proving `legacy_compatibility` is not enabled;
- pure Ed25519 valid vectors, altered message/key/signature rejection, and explicit rejection of Ed25519ctx/Ed25519ph substitutions;
- malformed or invalid authentication leaves application state unchanged, while any separately specified authenticated-action failure behavior is tested distinctly;
- acceptance/rejection comparisons across at least two independent implementations; if batching is introduced, differential equivalence with individual strict verification;
- each operation/domain/version substitution and cross-chain replay;
- truncation at every field boundary, trailing bytes, unsupported versions/codes, malformed length prefixes, invalid UTF-8, and size-limit boundaries;
- identical acceptance/rejection and state outcomes across at least two independent implementations;
- parser fuzzing, canonical round-trip/property tests, and deterministic replay from identical pre-state and ordered transactions.

## 12. Unresolved decisions and rejected alternatives

### Remaining unresolved decisions

- The NOVARA transaction-ID domain literal, whether the transaction ID includes the signature, and whether the existing `hash_transaction` helper matches the specified construction.
- Exact application-genesis schema and encoding for the approved Network ID, its secure generation/distribution procedure, and operational handling when creating an independent fork.
- Any fees or gas rules; this document defines none.
- Consensus feature-graph enforcement, complete cross-implementation conformance vectors, and application integration. The exact dependency pins and feature selection are implemented; the canonical point decoding rules and accepted subgroup, low-order, scalar, pure-Ed25519, strict-semantics, and no-state-mutation requirements above are approved and normative.
- Whether a future transaction type may add signed metadata or extension fields.

### Rejected alternatives

- Validators independently generating account IDs or deriving them from validator-local randomness.
- Treating an account ID as a public key or as proof of authorization.
- Encoding the same logical transaction in multiple accepted ways.
- Signing a presentation format or excluding state-changing fields from the signature.
- Reusing one authentication domain for different operations or protocol versions.
- Silently accepting malformed/noncanonical Ed25519 inputs based on a dependency's defaults.
- Enabling `legacy_compatibility`, replacing strict verification with ordinary verification, or introducing batch verification without proven conformance equivalence.
- Treating a NOVARA transaction ID as CometBFT's transaction hash.
- Using local wall-clock time for deterministic transaction validity.

## Status and implementation caveat

The 32-byte Network ID requirements, v1 canonical signing encoding and operation domains, account creation nonce and duplicate behavior, existing-account nonce consumption, validity and size bounds, and Strict Ed25519 rules are **APPROVED — NORMATIVE**. Transaction-ID derivation and operational/genesis details remain unresolved. The document remains a draft in other implementation and integration areas and does not claim production readiness.
