//! Emit only the first upstream public keygen commitment for hostile delivery tests.
//! No protocol simulation, completed key share, auxiliary material or signing nonce.
use cggmp24::{
    round_based::{Incoming, MessageDestination, MpcParty, Outgoing, ProtocolMessage},
    supported_curves::Secp256k1,
};
use futures_util::{sink, stream};
use std::io;
use wallet_mpc_protocol::dkg::DkgRequest;

type Msg = cggmp24::keygen::msg::threshold::Msg<
    Secp256k1,
    cggmp24::security_level::SecurityLevel128,
    sha2::Sha256,
>;

#[tokio::main]
async fn main() {
    let request: DkgRequest =
        serde_json::from_str(&std::env::args().nth(1).expect("binding required"))
            .expect("valid binding");
    let transcript = request.cggmp_transcript().expect("valid CGGMP request");
    let incoming = stream::pending::<Result<Incoming<Msg>, io::Error>>();
    let outgoing = Box::pin(sink::unfold((), |(), message: Outgoing<Msg>| async move {
        assert_eq!(message.recipient, MessageDestination::AllParties);
        println!(
            "{}",
            serde_json::json!({"round":message.msg.round(),"msg":message.msg})
        );
        Err::<(), io::Error>(io::Error::other("public fixture captured"))
    }));
    let _ = cggmp24::keygen::<Secp256k1>(cggmp24::ExecutionId::new(transcript.as_bytes()), 1, 3)
        .set_threshold(2)
        .start(
            &mut rand_core::OsRng,
            MpcParty::connected((incoming, outgoing)),
        )
        .await;
}
