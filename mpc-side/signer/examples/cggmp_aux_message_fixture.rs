//! Public synthetic messages for hostile transport tests. No primes, shares or nonces.
use cggmp24::round_based::ProtocolMessage;
fn main() {
    let byte: u8 = std::env::args().nth(1).unwrap().parse().unwrap();
    if std::env::args().nth(2).as_deref() == Some("sign") {
        let message = cggmp24::signing::msg::Msg::<cggmp24::supported_curves::Secp256k1, sha2::Sha256>::Round4(
            cggmp24::signing::msg::MsgRound4 { partial_sig: cggmp24::signing::PartialSignature { sigma: cggmp24::generic_ec::Scalar::from(u16::from(byte)) } },
        );
        println!("{}", serde_json::json!({"msg":message,"round":message.round()}));
    } else {
        let message = cggmp24::key_refresh::msg::Msg::<sha2::Sha256, cggmp24::security_level::SecurityLevel128>::Round1(
            cggmp24::key_refresh::msg::MsgRound1 { commitment: [byte; 32].into() },
        );
        println!("{}", serde_json::json!({"msg":message,"round":message.round()}));
    }
}
