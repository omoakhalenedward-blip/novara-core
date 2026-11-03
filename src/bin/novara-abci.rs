use std::{error::Error, path::PathBuf};

use novara_core::abci::application::NovaraApplication;
use tendermint_abci::ServerBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    let state_path = std::env::var_os("NOVARA_ABCI_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/novara-abci-state.bin"));
    let listen_address =
        std::env::var("NOVARA_ABCI_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:26658".to_owned());
    let application = NovaraApplication::open(state_path)?;
    let server = ServerBuilder::default().bind(&listen_address, application)?;

    eprintln!("NOVARA ABCI server listening at {listen_address}");
    server.listen()?;
    Ok(())
}
