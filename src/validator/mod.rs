//! NOVARA validator integration.
//!
//! CometBFT is responsible for:
//! - Validator voting power.
//! - Block proposals and voting.
//! - Consensus and block finality.
//!
//! NOVARA will provide application-level validator
//! management and communicate updates through ABCI.
//!
//! Validator keys are separate from ordinary wallet keys.
//!
//! This module is intentionally a foundation.
//! Validator registration and staking rules are not
//! implemented yet.
