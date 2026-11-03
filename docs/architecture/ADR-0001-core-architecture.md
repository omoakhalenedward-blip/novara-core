# ADR-0001: NOVARA Core Architecture

- **Status:** Founder-approved initial architecture direction; protocol details remain unresolved
- **Date:** 2026-11-02
- **Scope:** Initial architecture for NOVARA's independent Layer-1 protocol

## Purpose and scope

This ADR records the proposed boundaries and core principles for NOVARA's first engineering phase. It is intended to guide protocol specification and implementation planning; it does not define a complete wire protocol or authorize production deployment.

The ADR covers the Rust application and state machine, the proposed CometBFT consensus boundary, transaction and account responsibilities, state commitments, validator responsibilities, independent verification goals, security, and recovery. It does not settle tokenomics, exact cryptographic signing rules, canonical transaction encoding, database selection, or operational parameters.

**Status convention:** **CONFIRMED** identifies an existing implementation fact or a founder-approved initial architecture direction. **PROPOSED** identifies a recommendation not yet approved. **UNRESOLVED** identifies a decision requiring specification, testing, or explicit approval. **REJECTED** identifies an approach not recommended for this architecture. A confirmed direction does not mean its detailed protocol rules are complete or production-ready.

## Architectural principles

1. **Independent Layer-1 — CONFIRMED.** NOVARA defines and operates its own chain rules, state, assets, validator set, and application commitments. It is not specified as a token or application deployed on another chain.
2. **Deterministic state machine — CONFIRMED.** Given the same committed state and ordered block transactions, conforming application nodes must produce the same execution results, validator updates, and application commitment.
3. **Separation of responsibilities — CONFIRMED.** Unmodified CometBFT initially provides consensus, validator voting, finality, outer block format, and P2P networking. NOVARA's Rust application owns transaction validation, accounts, balances, assets, fees, staking, and deterministic execution.
4. **Canonical identities — CONFIRMED direction.** Distinguish CometBFT consensus identifiers from NOVARA application identifiers. Each NOVARA network has an immutable 32-byte Network ID generated once with a cryptographically secure random-number generator when the network is created and stored in application genesis state. Validators receive it through CometBFT `InitChain` and verify its exact length. Transactions and their signatures bind both this Network ID and the CometBFT Chain ID; validators reject mismatches. Wallets must compare the Network ID with trusted network configuration. An independent fork must receive a new Network ID. Copying a genesis file copies its Network ID, so it does not automatically create a distinct replay domain.
5. **Explicit commitments — PROPOSED.** Application state and proof semantics must be versioned and unambiguous. Committed data must have canonical encodings and documented hash domains.
6. **Verification without a trusted API — PROPOSED.** Wallets and merchants should eventually be able to verify consensus and application proofs independently using a trusted light-client checkpoint.
7. **Conservative execution — CONFIRMED.** Sequential deterministic execution is the initial protocol truth. Parallel execution, if considered later, must preserve exactly the sequential result.
8. **No unsupported guarantees.** Do not claim production readiness, performance, fee affordability, or economic security without implementation, testing, and evidence.

## System architecture

**CONFIRMED direction:** NOVARA initially consists of unmodified CometBFT as its outer consensus engine and a Rust application-specific state machine:

```text
Wallets, merchants, and integrations
              │ transactions / proof requests
              ▼
 NOVARA RPC and proof-serving interfaces
              │ untrusted transport; clients verify proofs
              ▼
       Unmodified CometBFT
       consensus · voting · finality · P2P
              │ ABCI boundary
              ▼
    Rust NOVARA deterministic application
     ├─ transaction validation and execution
     ├─ accounts, balances, assets, fees, and staking
     ├─ receipts and application commitments
     └─ storage, snapshots, and proof generation
              │
              ▼
       Persistent application state
```

The diagram is a target boundary, not a description of production services. The repository now includes a test-only ABCI++ smoke application and durable counter, but not a production execution engine, state tree, staking system, RPC service, or proof service.

**UNRESOLVED:** Whether the production application is embedded in the node process or operated as a separate process, and the production RPC and storage deployment model. The smoke experiment uses a separate process over the ABCI TCP socket.

## Consensus architecture

### Engine and responsibilities

**CONFIRMED direction:** Use unmodified CometBFT initially for consensus, validator voting, finality, outer block format, P2P networking, and block production. The Rust application remains authoritative for NOVARA transaction validation, accounts, balances, assets, fees, staking rules, deterministic execution, and application-defined validator updates.

CometBFT owns its consensus block structure, header fields, block hash, block identity, transaction-data commitment, and results commitment. ABCI application logic does not add arbitrary fields to the CometBFT header or redefine the engine's block-hash algorithm.

**EXPERIMENTALLY VERIFIED:** A test-only ABCI++ smoke application built with `tendermint-abci = 0.41.0` and `tendermint-proto = 0.41.0` connected to a one-validator CometBFT source build from tag `v0.40.0`. The live test covered the ABCI handshake, `CheckTx`, proposal processing, block execution, durable commit, the H+1 AppHash relationship, and recovery after restart. The binary's embedded Go module metadata identifies `v0.40.0`; its CLI reports `0.39.0` because that tag's fallback `TMCoreSemVer` constant is `0.39.0`.

**COMPATIBILITY LIMIT:** The Rust crate uses generated `v0_38` ABCI messages. The field tags used by the tested lifecycle callbacks matched CometBFT v0.40.0, but its request union does not include v0.40's `RequestInsertTx` and `RequestReapTxs` variants. The experiment therefore explicitly uses `mempool.type = "flood"`; CometBFT's app-mempool mode is not compatible with this adapter.

### Block identity

**CONFIRMED direction:** CometBFT's `BlockID` is the canonical consensus block identity used for consensus, parent linkage, and light-client verification. NOVARA may define application-level identifiers, but they must not be presented as substitutes for the consensus `BlockID`.

**CONFIRMED implementation detail:** The repository currently defines a 32-byte `BlockId` wrapper and a NOVARA-prefixed SHA-256 header hashing helper. This helper does not establish compatibility with CometBFT's block hash or full `BlockID`; its name and use must be reviewed before it is treated as a consensus block identifier.

**UNRESOLVED:** Whether to retain a distinct NOVARA application block reference for APIs or receipts, and how to represent CometBFT's full block identity, including its part-set information, in Rust interfaces.

### Lifecycle and validator updates

**PROPOSED:** Implement production ABCI++ lifecycle methods as a thin adapter around deterministic Rust application logic. Proposal preparation, proposal processing, finalization, and commit must follow the selected CometBFT version's requirements and be tested together. The current smoke adapter implements these callbacks only for its single test transaction and is not production transaction logic.

Validator-set changes are application-defined but delivered through CometBFT's validator-update mechanism. The application must model when updates become effective and preserve the historical validator set needed for evidence and accounting. Do not assume that a stake change takes effect immediately.

**UNRESOLVED:** Production release and compatibility policy beyond the tested flood-mempool smoke path, use of vote extensions or custom proposal logic, consensus parameters, validator key types, validator update timing in the selected version, and block limits.

## Transaction architecture

### Identifiers and encoding

**PROPOSED:** NOVARA transaction IDs remain distinct from CometBFT transaction hashes. CometBFT's transaction hash and inclusion proof refer to the raw transaction bytes committed in its block data. NOVARA's transaction ID is an application-level identifier whose derivation must be separately specified.

**CONFIRMED implementation detail:** A 32-byte `TransactionId` type and a NOVARA-domain-separated SHA-256 helper exist. Their exact use in a final transaction format has not been approved.

**CONFIRMED direction:** Every signed transaction binds the immutable 32-byte NOVARA Network ID as well as the CometBFT Chain ID. The application initializes its Network ID from genesis application state delivered through `InitChain`; the exact value is validated and thereafter immutable for that network.

**UNRESOLVED:** Canonical transaction encoding, transaction-ID input, exact signature preimage/domain literal, application-genesis schema and encoding, secure Network ID generation/distribution operations, nonce rules, expiry semantics, fee fields, and compatibility/versioning. The approved identity requirements do not prescribe all wire-format or operational details.

### Ordering and execution outcomes

**CONFIRMED direction:** Execute transactions in the block's defined order, sequentially and deterministically. Proposal selection or ordering must not allow nodes to derive different execution results for the same committed block.

Distinguish block rejection from a transaction that is included but fails execution. The protocol must define which malformed or invalid conditions reject a proposal and which produce a transaction-level failure result. It must also define nonce and fee effects for each outcome.

**UNRESOLVED:** Failure codes, fee charging, nonce consumption, resource metering, transaction and block limits, and whether particular invalid conditions invalidate the whole proposal.

## Account and authentication architecture

**PROPOSED:** The Rust application owns account creation, account state, authentication-policy validation, authorization, and key rotation rules. Account identifiers should be stable application identifiers, not assumed to be public keys unless that is explicitly decided.

**CONFIRMED implementation detail:** The repository has a fixed-size 32-byte `AccountAddress` type. This does not yet define address derivation, account creation, key representation, or authentication behavior.

**CONFIRMED direction:** Wallets must verify the Network ID against trusted network configuration before signing. Copying the same genesis copies the Network ID; forks intended as independent networks must establish and distribute a new ID.

**UNRESOLVED:** Key algorithms, public-key encoding, exact signing-byte construction, account creation and derivation, key rotation/recovery, multisignature or threshold policies, and wallet backup model. The network-identity binding is approved, but this ADR does not specify the complete transaction-signing format.

## State and storage architecture

**PROPOSED:** Application state is owned by the Rust state machine. State transitions, queries, validator updates, and commitments must be derived deterministically from the committed state and ordered transactions.

**CONFIRMED direction:** A Sparse Merkle Tree (SMT) is the preferred initial state-commitment design, subject to completing its specification. SHA-256 is the initial hash primitive, but the SMT's hash domains and construction rules remain unresolved. The database is a persistence mechanism, not the protocol definition: state keys, canonical values, and commitment rules must be specified independently of the selected storage engine.

**UNRESOLVED:** Database selection; atomic commit design; state pruning; snapshot format and retention; state-sync procedure; migrations and upgrades; SMT key derivation, leaf and node hashing, default hashes, bit order, proof format, and limits.

Do not treat a database checkpoint by itself as a complete application snapshot or recovery procedure.

## Application commitment and proof architecture

**PROPOSED:** Return a versioned application commitment containing the SMT root as the application's `AppHash`. The versioned structure should permit clients to identify the commitment format and, if justified, additional application roots. Its encoding and hash domain must be canonical and fully specified before protocol use.

CometBFT commits the application's returned hash in a subsequent block header according to its height semantics. Proof APIs and clients must identify the precise header height that authenticates a state or execution result.

CometBFT transaction inclusion proofs establish inclusion of raw transaction bytes in the block-data commitment. They do not alone prove successful execution or a successful payment. Execution results and application state require their own authenticated verification path.

**PROPOSED:** Design application proofs for account existence, balances, nonces, and payment receipts. Wallets and merchants should be able to verify a proof against the application commitment authenticated by a CometBFT light client.

**UNRESOLVED:** Exact top-level commitment encoding, root composition, proof format and versioning, receipt commitment strategy, proof serving interface, and trusted light-client checkpoint distribution.

## Validator and staking architecture

**CONFIRMED direction:** CometBFT owns validator voting. NOVARA's application owns staking and stake accounting, and supplies validator updates. Validator voting power must be converted deterministically to the integer representation accepted by the selected CometBFT release.

The application must track pending and effective validator sets, account for update activation delay, validate consensus evidence, and preserve the historical data needed to process evidence correctly.

**UNRESOLVED:** NVR supply and issuance, validator eligibility, active-set selection, stake-to-power conversion, delegation, commissions, rewards, fees, unbonding, redelegation, evidence windows, slashing, jailing, tombstoning, governance, and treasury policy. This ADR sets no token amounts, rates, fee values, or penalty percentages.

## Wallet and merchant verification

**PROPOSED:** Wallets and merchants should eventually verify chain activity independently rather than trusting a NOVARA-operated API. An API or gateway may provide transaction bytes, headers, validator sets, results, and application proofs, but clients must be able to validate them locally.

For a payment, the verification path must establish:

1. The expected transaction bytes and payment intent.
2. Inclusion in a CometBFT block using the block's transaction-data commitment.
3. A finalized CometBFT header and valid validator commit, verified from a trusted light-client checkpoint.
4. Successful application execution with a result bound to the transaction.
5. Where required by the acceptance policy, a receipt or resulting state proof bound to the authenticated application commitment.

A submission acknowledgment, mempool observation, unverified RPC response, or event alone is not proof of a successful payment.

**UNRESOLVED:** Client light-client implementation, trust-anchor onboarding and rotation, proof bundle schema, receipt retention, confirmation terminology, and merchant acceptance policies.

## Security requirements

**PROPOSED requirements:**

- Consensus execution must be deterministic and independent of local time, randomness, environment, external services, or nondeterministic iteration.
- Protocol encodings and committed data must be canonical and versioned.
- Hash uses must have clearly defined domains; no identifier or proof may rely on ambiguous encoding.
- Transaction authorization and replay protection must be defined before transactions are accepted on a public network.
- Arithmetic must be checked, and transaction, block, proof, execution, evidence, and storage work must have explicit limits.
- Consensus keys, node identity keys, and wallet authentication keys must have separated responsibilities and operational handling.
- Validator signing must protect against equivocation, stale backups, concurrent signers, and unsafe failover.
- Consensus-critical code and state transitions require deterministic replay, adversarial input testing, and independent security review before mainnet consideration.
- Public RPC and proof services must be treated as untrusted data sources and protected against abuse.

Exact cryptographic algorithms, signing rules, numeric limits, and operational configurations remain **UNRESOLVED** unless separately specified and approved.

## Recovery requirements

**PROPOSED requirements:**

- Persist application state, committed height, and application commitment consistently and atomically.
- On startup, report application height and hash consistent with the last successfully committed application state.
- Coordinate recovery testing across CometBFT block/state storage, consensus WAL, validator signer anti-double-sign state, and the Rust application's database.
- Define safe procedures for crash recovery, backup restoration, signer failover, state sync, and snapshot import.
- Version and validate application snapshots; verify restored state against a trusted application commitment.
- Inject crashes around finalization and commit boundaries and demonstrate deterministic recovery without double execution or divergent state.

**UNRESOLVED:** Exact database transaction boundaries, snapshot encoding, recovery runbooks, backup policy, and remote signer/HSM architecture.

## Decisions approved in principle

The following initial architecture directions have founder approval. This approval does not settle the protocol details listed as unresolved in this ADR:

| Decision | Status |
|---|---|
| NOVARA is an independent Layer-1. | **CONFIRMED — founder-approved direction** |
| Rust implements NOVARA's deterministic application and state machine, including transaction validation, accounts, balances, assets, fees, staking, and execution. | **CONFIRMED — founder-approved direction** |
| Unmodified CometBFT initially provides consensus, validator voting, finality, outer block format, P2P networking, and block production. | **CONFIRMED — founder-approved direction** |
| CometBFT's `BlockID` is the canonical consensus block identity. | **CONFIRMED — founder-approved direction** |
| NOVARA transaction IDs are distinct from CometBFT transaction hashes. | **PROPOSED** |
| SHA-256 is the initial hash primitive. | **CONFIRMED in existing code; protocol-wide use remains subject to specification** |
| A Sparse Merkle Tree is the preferred initial state commitment, subject to completing its specification. | **CONFIRMED — founder-approved direction** |
| Transaction execution begins sequentially and deterministically. | **CONFIRMED — founder-approved direction** |
| Payment verification establishes inclusion and successful execution, not merely submission. | **PROPOSED** |
| Wallets and merchants should eventually verify proofs independently. | **PROPOSED** |

## Unresolved decisions

Before freezing the protocol specification or implementing consensus-critical behavior, decide and document:

1. Which exact CometBFT release and Rust ABCI integration are supported, and whether their compatibility and operational behavior have been validated. The initial direction is to use unmodified CometBFT.
2. Whether the existing NOVARA header-hash helper remains an application utility, is renamed, or is removed from consensus identity paths.
3. Transaction encoding, identifier derivation, signing intent, account authentication, replay protection, expiry, nonce, fees, and failure semantics.
4. Application commitment encoding and hash domains; SMT rules and proof compatibility; receipt commitment and verification.
5. Database, atomic persistence, snapshot, state-sync, pruning, upgrade, and recovery procedures.
6. Validator selection, voting-power conversion, stake/delegation rules, update activation, evidence handling, and key operations.
7. All monetary, fee, reward, treasury, governance, and penalty policies. No parameters are set by this ADR.
8. Light-client trust anchors, wallet/merchant proof APIs, verification policies, and supported proof limits.
9. Protocol and execution resource limits, block acceptance criteria, monitoring, and incident-response requirements.

## Rejected approaches

- **REJECTED:** Treating a NOVARA-defined block hash as CometBFT's consensus `BlockID` when using unmodified CometBFT. The engine defines its own consensus block identity.
- **REJECTED for the initial architecture:** Modifying CometBFT to replace its consensus block format, validator voting, finality, or canonical `BlockID`.
- **REJECTED:** Treating NOVARA transaction IDs and CometBFT transaction hashes as interchangeable without an explicit equality specification.
- **REJECTED:** Treating transaction submission, mempool presence, inclusion alone, or an unauthenticated event as proof that a payment succeeded.
- **REJECTED:** Making parallel execution the initial protocol truth before equivalence to sequential deterministic execution is demonstrated.
- **REJECTED:** Choosing supply, issuance, fee, reward, or slashing numbers without an explicit economic analysis and protocol approval.
- **REJECTED:** Claiming production readiness or performance based only on architecture, compilation, or a functioning prototype.

## Implementation roadmap

1. **Validate architecture boundaries.** Implement and test the unmodified CometBFT integration while preserving CometBFT's ownership of consensus and canonical block identity.
2. **Write protocol specifications.** Define canonical transaction and receipt semantics, account/authentication requirements, state keys, commitments, proof formats, and failure outcomes. Do not invent unspecified cryptographic rules during implementation.
3. **Validate integration compatibility.** Pin the selected CometBFT release and Rust ABCI implementation; exercise the required ABCI++ lifecycle and validator updates in an integration environment.
4. **Implement deterministic state-machine foundations.** Begin with sequential execution and reproducible application commitments; add conformance vectors and replay tests.
5. **Establish persistence and recovery.** Select and test a database, atomic commit strategy, snapshots, state sync, and crash recovery.
6. **Build proof and client verification paths.** Verify CometBFT headers and transaction inclusion, then authenticate application results and state proofs.
7. **Run staged networks.** Progress from local development to private multi-validator testing, then public testnet only after deterministic, recovery, validator-update, and proof tests pass.
8. **Complete security and operational review.** Fuzz parsers and proof verifiers, test partitions and crash cases, audit consensus-sensitive code, and document validator operations before any mainnet decision.

This roadmap is conditional. It does not establish a launch date or claim that any stage is complete.

## Acceptance criteria

This ADR is ready for approval as a proposed architecture when reviewers agree that:

- The founder-approved unmodified-CometBFT/Rust responsibility boundary and its constraints are explicit.
- Consensus `BlockID` and NOVARA transaction-ID semantics are not conflated.
- The versioned SMT-based application commitment is recorded as a preference, not an already implemented or fully specified feature.
- Sequential deterministic execution is the initial execution model.
- Payment verification requires authenticated inclusion and successful execution.
- The independent-verification goal, security requirements, and recovery responsibilities are documented.
- All unresolved protocol and economic choices are visibly left open; no unsupported numeric parameters are introduced.
- The document does not imply production readiness.

Before implementation is considered conformant to this ADR, the project must additionally demonstrate through tests that transaction execution and commitments are deterministic, proof roots are correctly anchored to verified CometBFT headers, and recovery restores a consistent committed application state. Mainnet readiness requires separate security, economic, and operational gates.
