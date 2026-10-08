//! Public synthetic commitment for transport rejection tests. No primes or shares.
use cggmp24::round_based::ProtocolMessage;
fn main() {
    let byte: u8 = std::env::args().nth(1).unwrap().parse().unwrap();
    let message = cggmp24::key_refresh::msg::Msg::<sha2::Sha256, cggmp24::security_level::SecurityLevel128>::Round1(
        cggmp24::key_refresh::msg::MsgRound1 { commitment: [byte; 32].into() },
    );
    println!("{}", serde_json::json!({"msg":message,"round":message.round()}));
}
