NOVARA Genesis Format V1

Status: Initial specification
Format version: 1
Network: NOVARA Layer-1

1. Purpose

The genesis configuration establishes the initial identity of a NOVARA blockchain network.

Every validator belonging to the same network must use the same genesis configuration and Network ID.

2. Genesis V1 fields

Genesis V1 contains:

- Genesis format version.
- Network ID.

Initial account allocations, validator allocations and tokenomics are reserved for future specifications.

3. Binary encoding

Genesis V1 uses a strict, deterministic binary encoding.

The encoded structure contains exactly 44 bytes:

Field| Length
Magic bytes ("NVRGEN" followed by two zero bytes)| 8 bytes
Format version| 4 bytes
Network ID| 32 bytes
Total| 44 bytes

The format version is an unsigned 32-bit integer encoded in big-endian byte order.

The Network ID is exactly 32 bytes.

4. Network ID generation

The Network ID must be generated using a cryptographically secure random number generator.

It must be generated once when creating a network's genesis configuration.

Validators must receive and validate the established Network ID. They must never independently generate their own Network IDs during initialization.

5. Validation rules

A validator must reject genesis data when:

- The magic bytes are incorrect.
- The encoded length is not exactly 44 bytes.
- The format version is unsupported.
- The Network ID is missing or malformed.

No default Network ID may be assigned when validation fails.

6. Network identity

The Network ID uniquely identifies a NOVARA network.

Transactions and signatures must bind to the appropriate network identity.

A different network must use a separately generated Network ID.

7. Future extensions

Future genesis versions may introduce:

- Initial NVR supply.
- Initial account allocations.
- Validator configuration.
- Staking parameters.
- Network economic parameters.

Such additions must be introduced through an explicitly versioned specification.

8. Compatibility

Genesis V1 implementations must follow this specification exactly.

Unknown versions must be rejected rather than silently interpreted as version 1.
