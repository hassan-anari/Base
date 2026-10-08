//! Bounded, direct mTLS delivery for the pinned round-based protocol API.
use crate::ProtocolEnvelope;
use cggmp24::round_based::{Incoming, MessageDestination, MessageType, Outgoing, ProtocolMessage};
use futures_util::{sink, stream, Sink, Stream, StreamExt};
use serde::{de::DeserializeOwned, Serialize};
use std::io;
use tokio::sync::mpsc;
use wallet_mpc_protocol::dkg::DkgRequest;
use wallet_mpc_transport::SignerClient;
use zeroize::Zeroizing;

pub(super) fn delivery<M>(
    request: DkgRequest,
    own: String,
    peers: SignerClient,
    inbox: mpsc::Receiver<ProtocolEnvelope>,
) -> (
    impl Stream<Item = Result<Incoming<M>, io::Error>> + Unpin,
    impl Sink<Outgoing<M>, Error = io::Error> + Unpin,
)
where
    M: Serialize + DeserializeOwned + ProtocolMessage + Send + 'static,
{
    let incoming = Box::pin(
        stream::unfold(inbox, |mut inbox| async move {
            inbox.recv().await.map(|msg| (msg, inbox))
        })
        .map(|mut wire| {
            let payload = Zeroizing::new(std::mem::take(&mut wire.payload));
            let msg: M = serde_json::from_slice(&payload).map_err(io::Error::other)?;
            let sender = wallet_mpc_protocol::dkg::PARTIES
                .iter()
                .position(|p| *p == wire.sender)
                .ok_or_else(|| io::Error::other("unknown sender"))? as u16;
            Ok(Incoming {
                id: u64::from(sender) * 128 + wire.sequence,
                sender,
                msg_type: if wire.protocol.ends_with("/broadcast") {
                    MessageType::Broadcast
                } else {
                    MessageType::P2P
                },
                msg,
            })
        }),
    );
    let outgoing = Box::pin(sink::unfold(
        (request, own, peers, 0u64),
        |(request, own, peers, sequence), outgoing: Outgoing<M>| async move {
            let broadcast = outgoing.recipient == MessageDestination::AllParties;
            let recipients = match outgoing.recipient {
                MessageDestination::AllParties => request
                    .participants
                    .iter()
                    .filter(|p| **p != own)
                    .cloned()
                    .collect::<Vec<_>>(),
                MessageDestination::OneParty(index) => vec![request
                    .participants
                    .get(usize::from(index))
                    .ok_or_else(|| io::Error::other("invalid recipient"))?
                    .clone()],
            };
            if sequence >= 64 {
                return Err(io::Error::other("message budget exceeded"));
            }
            let payload =
                Zeroizing::new(serde_json::to_vec(&outgoing.msg).map_err(io::Error::other)?);
            for recipient in recipients {
                if recipient == own {
                    return Err(io::Error::other("self message"));
                }
                let mut wire = ProtocolEnvelope {
                    logical_session_id: request.session_id,
                    crypto_execution_id: request.execution_id,
                    keyset_id: request.keyset_id,
                    protocol: format!(
                        "{}/{}",
                        request.cggmp_transcript().map_err(io::Error::other)?,
                        if broadcast { "broadcast" } else { "p2p" }
                    ),
                    sender: own.clone(),
                    recipient: recipient.clone(),
                    round: outgoing.msg.round(),
                    sequence,
                    payload: payload.to_vec(),
                    payload_digest: String::new(),
                };
                wire.payload_digest = wire.transcript_digest();
                let body = serde_json::to_vec(&wire).map_err(io::Error::other)?;
                use zeroize::Zeroize;
                wire.payload.zeroize();
                peers
                    .request(
                        &recipient,
                        "POST",
                        "/internal/v1/cggmp/keygen/message",
                        body,
                    )
                    .await
                    .map_err(|_| io::Error::other("CGGMP peer delivery failed"))?;
            }
            Ok((request, own, peers, sequence + 1))
        },
    ));
    (incoming, outgoing)
}
