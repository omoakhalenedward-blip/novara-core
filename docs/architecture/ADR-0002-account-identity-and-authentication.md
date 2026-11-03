# ADR-0002: Account Identity and Authentication

- **Status:** Account identity and Strict Ed25519 rules approved and normative; remaining implementation details unresolved
- **Date:** 2026-11-02
- **Scope:** Stable account identifiers, initial account authentication, and authorization-key rotation

## Context

NOVARA needs account identities that remain stable independently of the credentials used to authorize transactions. Authentication messages must be unambiguous and bound to their intended network, CometBFT chain, and purpose. The initial implementation should be small enough to test thoroughly while leaving room for future authentication policies.

This ADR records approved normative account-identity, signing, authentication, and nonce rules alongside remaining unresolved implementation details. It does not describe the smoke application's behavior or establish production readiness.

## Decisions and unresolved details

### Network identity — approved direction

1. Each NOVARA network has one immutable Network ID of exactly 32 bytes. It is generated once, when the network is created, using a cryptographically secure random-number generator, and stored in the application's genesis state.
2. Validators receive the application genesis state through CometBFT `InitChain` and must verify that the Network ID is exactly 32 bytes. A malformed or absent ID must not be silently defaulted or replaced by validator-local randomness.
3. Every signed transaction includes the Network ID in its canonical signing message, in addition to the CometBFT Chain ID. Validators reject a transaction unless both identifiers match the values initialized for their network.
4. Wallets must verify the Network ID against trusted network configuration before signing; an identifier supplied only by an untrusted RPC endpoint is insufficient.
5. The Network ID is immutable for the network's lifetime. A fork intended to operate as an independent network must be assigned a new Network ID. Copying a genesis file copies its Network ID, so copying alone does not create an independent transaction replay domain.

The identity requirements above are approved. The application-genesis schema, exact encoding and initialization failure behavior, secure generation and distribution procedure, and operational coordination for fork IDs remain implementation details to specify. These details must preserve the approved requirements. A shared ID intentionally means transactions are in the same network replay domain; changing it is an explicit network-creation/fork decision, not a validator-local action.

### Account identity

1. An account identifier is an opaque, fixed-width 32-byte value.
2. The identifier is a stable reference to the account, not a public key, public-key hash, or authentication credential. It remains unchanged when authentication keys are rotated.
3. Code must not infer the authentication key or account ownership from the identifier's bytes.
4. The client creates the identifier using a cryptographically secure random-number generator and includes the resulting 32 bytes in the signed account-creation transaction. Validators must never generate account identifiers independently or replace a submitted identifier.
5. Account creation is rejected if the identifier already exists in the pre-state or was created earlier in the same ordered block. The check and account creation are deterministic state transitions; a collision never overwrites or changes the existing account.
6. This client-generated scheme makes accidental collisions negligibly likely, but does not prove that a client used a secure random generator or prevent a malicious client from choosing another account's identifier. The signature proves control of the proposed initial key, not exclusive ownership of an opaque identifier before it is registered. Client-side CSPRNG requirements, operational rate limiting, and whether a separate proof of identifier generation is needed remain unresolved.
7. Account state stores the identifier and the active authentication policy separately. It must not store private keys.

`AccountAddress` remains an opaque 32-byte byte-container type. The isolated `account` module now enforces creation and authentication semantics without changing that shared type.

The identity-generation and duplicate-ID rules above are **APPROVED — NORMATIVE**. Account IDs are client-generated 32-byte opaque values, creation uses nonce 0, and a successfully created account's next nonce is 1. Duplicate creation is rejected without replacing the existing account, key, or nonce.

### Initial authentication policy

1. Ed25519 is the approved initial signature algorithm under the NOVARA Strict Ed25519 policy below.
2. An account has exactly one registered Ed25519 public key under the initial policy. **APPROVED — NORMATIVE: NOVARA STRICT ED25519 POLICY.** Public keys are exactly 32 bytes and signatures exactly 64 bytes; reject other lengths before parsing or verification. A point encoding is the 32-byte compressed Edwards-Y form: the low 255 bits encode `y` as a little-endian integer and the high bit encodes the sign of `x`. Require `y < 2^255 - 19`; reject an encoding that fails point decompression, and reject `x = 0` with sign bit 1. Re-encoding a decoded point must reproduce the input bytes exactly. Apply these rules to public-key point `A` and signature point `R`; both points must belong to the prime-order subgroup and must not be small-order, including the identity. Signature scalar `S` is a canonical little-endian scalar satisfying `0 <= S < L`. Use pure Ed25519 with strict verification semantics, not Ed25519ctx or Ed25519ph. All validators must implement exactly the same acceptance rules. Malformed or invalid authentication must never mutate application state or consume a nonce.
3. Private keys are held by the account controller (for example, in a wallet or hardware-backed signer) and must never be written to consensus state, application databases, transaction events, logs, or ABCI responses.
4. A signature authorizes only the message type and canonical bytes for which it was produced. Signatures must be verified against the account's currently registered key and the account identifier named in the message.
5. For account creation, the transaction carries the submitted account identifier and proposed initial public key, and the client signs the complete creation message with the corresponding private key. Validators verify that signature against the proposed public key before creating state. This proves control of that key for the creation request; it does not make the public key the account identifier.
6. Wallet authentication keys are distinct from CometBFT validator consensus-signing keys and CometBFT node identity keys. They have separate purposes and must not be reused or treated as interchangeable.
7. Key recovery after loss or compromise requires a separate protocol decision. There is no implicit administrator or keyless recovery authority in this initial policy.

### Ed25519 implementation candidates and verification semantics

**IMPLEMENTED DEPENDENCIES:** `ed25519-dalek` 2.2.0 and direct `curve25519-dalek` 4.1.3 dependencies are pinned exactly with default features disabled. The dedicated `crypto::ed25519` verifier performs the normative point/scalar checks and calls `verify_strict`; the direct curve dependency provides the explicit compressed-point decoding, re-encoding, subgroup, and small-order checks. Consensus feature resolution must continue to be checked for `legacy_compatibility`.

The verifier enforces the normative field and sign-bit rules, parses with `VerifyingKey::from_bytes`, independently decompresses `A` and `R` using `CompressedEdwardsY`, requires each point's compressed re-encoding to match the supplied bytes, requires `is_torsion_free()` and `!is_small_order()` for each, parses the fixed-length signature, then calls `VerifyingKey::verify_strict(message, &signature)`. Verify feature resolution for every consensus build.

The crate's `VerifyingKey::from_bytes` documents ZIP-215 point decoding, not NOVARA's complete canonicality or subgroup policy. `verify_strict` checks scalar canonicality and rejects small-order public keys and `R`, but does not by itself establish the normative `y` bound, byte-canonical point encodings, or prime-order subgroup membership for both points. Those checks must be explicit. The `legacy_compatibility` feature relaxes the scalar check and must not be enabled in consensus builds. Ordinary `verify()` must not replace `verify_strict()`. Batch verification must not be introduced unless conformance testing proves it accepts and rejects exactly the same inputs as the approved individual strict path.

The crate's strict method is documented as technically non-RFC-8032-compliant because it intentionally rejects additional malleable cases. NOVARA's approved rule is its own strict acceptance profile; it must not be labeled ZIP-215. The dependency pins and verifier are implemented, but consensus integration, feature-graph enforcement in all build configurations, conformance vectors beyond this module, and independent implementation comparison remain outstanding.

References:

- [`ed25519-dalek` 2.2.0 `VerifyingKey` documentation](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html)
- [`ed25519-dalek` 2.2.0 verification source](https://docs.rs/ed25519-dalek/2.2.0/src/ed25519_dalek/verifying.rs.html)
- [ZIP-215 point-encoding specification](https://zips.z.cash/zip-0215)

### Canonical authorization messages

**APPROVED — NORMATIVE:** V1 authentication uses pure Ed25519 over a canonical binary encoding. All integers are unsigned big-endian, fixed-width; the Chain ID is exact UTF-8 bytes with a `u16` big-endian byte-length prefix. The complete ordered fields are: 8-byte magic `NOVATX1\0`; `u16` format version 1; 32-byte NOVARA Network ID; Chain ID (1–50 UTF-8 bytes); 32-byte account ID; `u64` nonce; `u64` valid-from height; `u64` expiry height; `u8` operation code; exact 32-byte operation payload; and, only in the complete transaction, the 64-byte signature. Signing excludes the signature field and prefixes the unsigned fields with an operation-specific domain:

- Account creation: ASCII `NOVARA::AUTH::CREATE::V1\0`.
- Key rotation: ASCII `NOVARA::AUTH::ROTATE::V1\0`.

The signature therefore binds the Network ID, CometBFT Chain ID, account ID, nonce, validity limits, version, operation, and all operation-specific bytes. The domain tags and operation codes prevent cross-operation and cross-version signature reuse. Unknown versions, noncanonical field encodings, invalid UTF-8, truncation, trailing bytes, and fields outside the normative limits are rejected. The maximum complete transaction is 1,024 bytes. The validity window is inclusive, requires `valid_from <= expiry`, spans at most 100,000 height increments, and uses heights no greater than `i64::MAX`; validators use the execution block height, never local time.

This exact encoding is specified in [transaction-format-v1.md](../protocol/transaction-format-v1.md). Transaction-ID derivation remains unresolved and is separate from authentication signing.

### Replay protection and account nonce

Every authenticated state-changing operation on an existing account, including key rotation, must be bound to the NOVARA Network ID, CometBFT Chain ID, and account nonce. The application must reject a wrong-network or wrong-chain message and a nonce that is not the next valid nonce under the protocol's specified rule. Nonces are account state, not part of the account identifier.

**APPROVED — NORMATIVE:** Account creation uses nonce 0; after successful creation, the next expected nonce is 1. For an existing account, an included transaction consumes its expected nonce after authentication under the current key, even if the requested operation fails. Invalid authentication—including a bad signature, wrong network or chain, wrong account, invalid validity window, missing account, or replayed/out-of-order nonce—consumes no nonce and changes no account state. A failed authenticated action has a failed result while its nonce increment remains committed. Nonce increments use checked arithmetic and never wrap.

Nonce validation, nonce consumption, and action state changes must be applied atomically and deterministically. If authentication succeeds but the action fails, only the authenticated nonce increment remains; prohibited partial action effects do not. A transaction at `u64::MAX` is rejected without mutation because its nonce cannot be incremented.

Account creation is a separate authentication path: its signature is checked against the proposed initial public key, and the submitted ID must be absent. Duplicate creation is rejected without modifying the existing account, its public key, or its nonce. A colliding create never authorizes or consumes a nonce from the existing account.

### Key rotation

1. A key-rotation operation names the stable account identifier, the current account nonce, and the proposed new Ed25519 public key; all are bound into the canonical key-rotation signing message.
2. The operation must be signed by the currently registered key and verified against that key before the registered key is changed.
3. A proposed new key must pass the same canonical public-key encoding and input validation as an initial key.
4. Successful rotation replaces the registered public key and consumes the authenticated transaction's nonce atomically; the account identifier never changes.
5. A replayed rotation is rejected because its nonce is no longer current. After rotation, new authorizations use the new key; the old key is no longer authorized. Rotation and nonce changes must not be partially applied.
6. This proposal has no dual-signature, guardian, delayed recovery, or administrator override path. Recovery policy remains unresolved.

### Deterministic account and policy transitions

Clients choose random account IDs before submission; validators do not generate or repair IDs. Given identical pre-state and the same ordered block transactions, every validator checks the same submitted ID, signature, nonce, current key, and existence condition, then applies the same transition. Account creation succeeds only if the submitted ID is absent at that point in sequential execution. A rotation succeeds only if its signature verifies under the pre-transition registered key and its nonce is current; the authorized nonce and new key are committed atomically. Duplicate IDs, duplicate or stale rotations, and other failed operations produce deterministic outcomes without overwriting existing account state.

No consensus decision may depend on validator-local randomness, wall-clock time, process environment, or iteration order. Client randomness is not re-sampled or interpreted by validators; validators only validate and process the submitted bytes under the deterministic rules.

## Security requirements

- Use a maintained Ed25519 implementation with clear verification semantics; reject malformed key and signature lengths before verification.
- Enforce the approved — normative strict Ed25519 profile identically across validators: exact lengths; for `A` and `R`, compressed Edwards-Y encoding with `y < 2^255 - 19`, successful decompression, rejection of `x = 0` with sign bit 1, exact re-encoding equality, prime-order subgroup membership, and rejection of small-order points including identity; canonical `S` with `0 <= S < L`; pure Ed25519; and strict verification semantics.
- Keep `legacy_compatibility` disabled in consensus builds. Never replace strict verification with ordinary permissive verification. Do not introduce batch verification unless conformance tests prove exact acceptance equivalence.
- Malformed or invalid authentication must not mutate application state. This does not change the separately proposed nonce rule for an authenticated transaction whose requested action fails.
- Compare and process credentials without logging sensitive key material. Redact public operational logs where keys could otherwise become account-linking data; never expose private keys.
- Keep wallet authentication keys separate from CometBFT validator consensus keys and node identity keys.
- Authenticate both the NOVARA Network ID and CometBFT Chain ID, as well as account, purpose, protocol/message version, nonce, validity limits, and all state-changing fields in the canonical signing preimage.
- Use separate domain tags for different operation types and versions to prevent cross-protocol and cross-purpose signature replay.
- Reject noncanonical encodings instead of normalizing them silently.
- Apply strict input and resource limits before allocation or cryptographic verification.
- Keep account identity derivation independent of authentication-key generation and rotation. Do not treat possession of an account identifier as authority.
- Verify key rotation against the pre-transition registered key, and commit the key and nonce changes atomically.
- Use checked nonce and balance arithmetic in state transitions; this ADR does not define balance or asset semantics.
- Do not claim cryptographic security based only on successful compilation or happy-path tests. Consensus-critical code requires adversarial testing and independent review before production use.

## Required tests

Before this design is used for production transactions, tests must include:

- Account identifiers are exactly 32 bytes, are treated as opaque values, and remain unchanged when authentication keys rotate.
- Account creation includes a client-generated ID in the signed message; validators never generate IDs, duplicate IDs are rejected, and a collision cannot alter the existing account.
- Valid Ed25519 signatures verify for fixed test vectors; altered messages, keys, or signatures fail.
- Fixed vectors cover pure Ed25519 and the NOVARA signing preimage, valid cases, altered messages, wrong lengths, `y` at and above `2^255 - 19`, failed decompression, `x = 0` with either sign bit, and exact decode/re-encode behavior.
- Boundary vectors cover `S = L-1` acceptance and `S = L`, `L+1`, and other noncanonical encodings rejection; consensus builds verify `legacy_compatibility` is disabled.
- Point vectors cover canonical `A` and `R`, noncanonical aliases (including noncanonical `y` and the `x = 0` sign-bit case), invalid decompressions, every low-order encoding including identity, mixed-torsion points, and prime-subgroup versus torsion-bearing points.
- Fixed cross-implementation vectors establish identical acceptance/rejection behavior for all approved cases across at least two independent implementations.
- If batch verification is considered, its complete acceptance set is differentially tested against the individual strict path before use.
- Wrong Network IDs or CometBFT Chain IDs, account identifiers, nonces, message versions, and operation-purpose domain tags fail verification.
- Genesis initialization rejects a missing or non-32-byte Network ID; validators agree on the initialized value, do not change it during the network lifetime, and reject transactions carrying another value.
- Wallets compare the configured Network ID with a trusted source before signing. Tests document that copied genesis files copy the ID and exercise the distinct-ID requirement for independent forks.
- Transaction authorization signatures cannot authorize key rotation, and key-rotation signatures cannot authorize another operation.
- Encoders produce stable canonical bytes. Decoders reject truncation, trailing bytes, invalid lengths, noncanonical encodings, duplicate fields, and unsupported versions.
- Replayed and out-of-order nonces are rejected without changing account state. Authenticated included actions that fail still consume exactly one nonce; invalid authentication consumes none. Nonce overflow fails without wrapping.
- Replaying a successful key rotation or submitting one signed by a stale key is rejected; account ID remains unchanged.
- Identical creation and rotation transactions applied to identical state in the same order produce identical state and result across independent validators.
- Rotation signed by the current key succeeds once; rotation signed only by an unrelated or previously replaced key fails; the new key authorizes subsequent operations.
- Failed or interrupted rotation leaves the account's key and nonce in a consistent pre- or post-transition state, never a partial state.
- Private key material does not appear in persisted application state, logs, events, or ABCI responses.
- Deterministic execution tests produce identical account state and commitments for identical starting state and ordered messages.
- Fuzz tests cover transaction and signature-message parsers, and property tests cover canonical encode/decode round trips.

## Unresolved decisions

- The client CSPRNG requirements and operational safeguards against maliciously chosen or repeated account IDs; validators only enforce the 32-byte format and state-level uniqueness rule.
- Consensus feature-set enforcement, independent implementation comparison, durable persistence and integration into authenticated transaction execution. The canonical signing rules and the isolated account-state implementation do not yet enable v1 transaction execution in ABCI.
- Transaction-ID derivation and its relationship, if any, to the canonical signed bytes.
- Client CSPRNG operational guidance and protection against deliberate account-ID squatting; clients generate IDs, while validators enforce format and uniqueness.
- Whether future non-state-changing operations require nonces.
- Account recovery, lost-key handling, compromised-key response, and whether any recovery authority should exist.
- Public-key rotation history, key revocation evidence, and privacy implications of exposing keys in state.
- Mapping or migration from the current `AccountAddress` type to the specified opaque identifier.
- Threshold or multi-party authentication policy and its state representation.
- Any authentication algorithms beyond the approved initial Ed25519 policy.

## Future threshold authentication

Threshold or multi-party authentication is intentionally out of scope for the initial single-key policy. Future support should be introduced as an explicitly versioned authentication policy associated with the same stable account identifier, not by changing the account identifier. Its signer-set encoding, threshold rules, key aggregation or share model, rotation and recovery semantics, verification costs, and canonical signing messages require a separate specification and security review. No threshold scheme or compatibility guarantee is approved by this ADR.

## Consequences

This proposal separates durable account identity from replaceable authorization credentials. The isolated account module implements in-memory account creation, strict authentication, nonce tracking, and key rotation against the approved signing encoding. It is not integrated into ABCI, does not provide durable account persistence or full transaction parsing/execution, and does not authorize production use. Protocol details marked unresolved must be decided, specified, and tested before production transactions are enabled.
