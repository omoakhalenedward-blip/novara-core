use std::path::Path;

use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    ExecTxResult, RequestCheckTx, RequestFinalizeBlock, RequestInfo, RequestInitChain,
    RequestPrepareProposal, RequestProcessProposal, ResponseCheckTx, ResponseCommit,
    ResponseFinalizeBlock, ResponseInfo, ResponseInitChain, ResponsePrepareProposal,
    ResponseProcessProposal, response_process_proposal::ProposalStatus,
};

use crate::app::smoke_state::{SMOKE_TRANSACTION, SmokeState, StateSnapshot};

const CODE_OK: u32 = 0;
const CODE_INVALID_TX: u32 = 1;
const APP_VERSION: u64 = 1;

#[derive(Clone, Debug)]
pub struct NovaraApplication {
    state: SmokeState,
}

impl NovaraApplication {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, crate::app::smoke_state::SmokeStateError> {
        Ok(Self {
            state: SmokeState::open(path.as_ref())?,
        })
    }

    pub fn state_snapshot(&self) -> StateSnapshot {
        self.state.snapshot()
    }
}

impl Application for NovaraApplication {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let snapshot = self.state.snapshot();
        ResponseInfo {
            data: "NOVARA ABCI++ smoke application".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: APP_VERSION,
            last_block_height: snapshot.height,
            last_block_app_hash: snapshot.app_hash.to_vec().into(),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        let snapshot = self
            .state
            .initialize(request.initial_height)
            .expect("NOVARA smoke application failed to initialize");
        ResponseInitChain {
            consensus_params: None,
            validators: Vec::new(),
            app_hash: snapshot.app_hash.to_vec().into(),
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        let valid = request.tx.as_ref() == SMOKE_TRANSACTION;
        ResponseCheckTx {
            code: if valid { CODE_OK } else { CODE_INVALID_TX },
            data: Vec::new().into(),
            log: if valid {
                String::new()
            } else {
                "invalid smoke transaction".to_owned()
            },
            info: String::new(),
            gas_wanted: i64::from(valid),
            gas_used: 0,
            events: Vec::new(),
            codespace: if valid {
                String::new()
            } else {
                "novara-smoke".to_owned()
            },
        }
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        let max_tx_bytes = usize::try_from(request.max_tx_bytes).unwrap_or(0);
        let mut total_bytes = 0usize;
        let txs = request
            .txs
            .into_iter()
            .filter(|tx| tx.as_ref() == SMOKE_TRANSACTION)
            .take_while(|tx| {
                let Some(next_total) = total_bytes.checked_add(tx.len()) else {
                    return false;
                };
                if next_total > max_tx_bytes {
                    return false;
                }
                total_bytes = next_total;
                true
            })
            .collect();

        ResponsePrepareProposal { txs }
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        let status = if self
            .state
            .can_process_proposal(request.height, &request.txs)
        {
            ProposalStatus::Accept
        } else {
            ProposalStatus::Reject
        };
        ResponseProcessProposal {
            status: status as i32,
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let result = self
            .state
            .finalize_block(request.height, &request.txs)
            .expect("NOVARA smoke application failed to finalize block");
        let tx_results = result
            .successful_transactions
            .into_iter()
            .map(|success| ExecTxResult {
                code: if success { CODE_OK } else { CODE_INVALID_TX },
                data: Vec::new().into(),
                log: if success {
                    String::new()
                } else {
                    "invalid smoke transaction".to_owned()
                },
                info: String::new(),
                gas_wanted: i64::from(success),
                gas_used: i64::from(success),
                events: Vec::new(),
                codespace: if success {
                    String::new()
                } else {
                    "novara-smoke".to_owned()
                },
            })
            .collect();

        ResponseFinalizeBlock {
            events: Vec::new(),
            tx_results,
            validator_updates: Vec::new(),
            consensus_param_updates: None,
            app_hash: result.state.app_hash.to_vec().into(),
        }
    }

    fn commit(&self) -> ResponseCommit {
        self.state
            .commit()
            .expect("NOVARA smoke application failed to persist committed state");
        ResponseCommit { retain_height: 0 }
    }
}
