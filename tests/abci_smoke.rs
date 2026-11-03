use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use novara_core::{
    abci::application::NovaraApplication,
    app::smoke_state::{SMOKE_TRANSACTION, SmokeState, SmokeStateError},
    genesis::{GenesisConfig, NetworkId},
};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    RequestCheckTx, RequestFinalizeBlock, RequestInfo, RequestInitChain, RequestPrepareProposal,
    RequestProcessProposal, response_process_proposal::ProposalStatus,
};

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "novara-abci-smoke-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    fn state_path(&self) -> PathBuf {
        self.0.join("state.bin")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove isolated test directory");
    }
}

fn genesis_bytes(seed: u8) -> Vec<u8> {
    let network_id = NetworkId::new([seed; 32]);
    GenesisConfig::new(1, network_id)
        .unwrap()
        .encode()
        .unwrap()
}

fn init_request(seed: u8) -> RequestInitChain {
    RequestInitChain {
        initial_height: 1,
        app_state_bytes: genesis_bytes(seed).into(),
        ..Default::default()
    }
}

#[test]
fn check_tx_validates_without_mutating_committed_state() {
    let directory = TestDirectory::new();
    let app = NovaraApplication::open(directory.state_path()).unwrap();

    let accepted = app.check_tx(RequestCheckTx {
        tx: SMOKE_TRANSACTION.to_vec().into(),
        r#type: 0,
    });
    let rejected = app.check_tx(RequestCheckTx {
        tx: b"not-a-smoke-transaction".to_vec().into(),
        r#type: 0,
    });

    assert_eq!(accepted.code, 0);
    assert_eq!(rejected.code, 1);
    let info = app.info(RequestInfo::default());
    assert_eq!(info.last_block_height, 0);
    assert_eq!(app.state_snapshot().smoke_counter, 0);
}

#[test]
fn proposal_processing_and_finalization_are_deterministic_and_staged() {
    let first_directory = TestDirectory::new();
    let second_directory = TestDirectory::new();
    let first = NovaraApplication::open(first_directory.state_path()).unwrap();
    let second = NovaraApplication::open(second_directory.state_path()).unwrap();

    first.init_chain(init_request(1));
    second.init_chain(init_request(1));

    let prepared = first.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: SMOKE_TRANSACTION.len() as i64,
        txs: vec![
            b"invalid".to_vec().into(),
            SMOKE_TRANSACTION.to_vec().into(),
        ],
        ..Default::default()
    });
    assert_eq!(prepared.txs.len(), 1);
    assert_eq!(prepared.txs[0].as_ref(), SMOKE_TRANSACTION);

    let proposal = RequestProcessProposal {
        height: 1,
        txs: prepared.txs.clone(),
        ..Default::default()
    };
    let first_response = first.process_proposal(proposal.clone());
    let second_response = first.process_proposal(proposal);
    assert_eq!(first_response.status, ProposalStatus::Accept as i32);
    assert_eq!(first_response, second_response);
    assert_eq!(first.state_snapshot().smoke_counter, 0);

    let request = RequestFinalizeBlock {
        height: 1,
        txs: prepared.txs,
        ..Default::default()
    };
    let first_result = first.finalize_block(request.clone());
    let second_result = second.finalize_block(request);
    assert_eq!(first_result.app_hash, second_result.app_hash);
}
