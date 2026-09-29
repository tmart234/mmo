//! Every message a peer can send, decoded exactly as the receive paths do.
#![no_main]

use common::framing::{decode_frame, MAX_CONTROL_FRAME, MAX_SNAPSHOT_FRAME, MAX_TRANSCRIPT_FRAME};
use common::proto::{
    ClientHello, ClientInput, ClientToGs, GsToClient, Heartbeat, JoinAccept, JoinRequest,
    PlayTicket, ProtectedReceipt, ServerHello, TranscriptDigest,
};
use common::tpm::TpmQuote;
use libfuzzer_sys::fuzz_target;

fn decode<T: serde::de::DeserializeOwned>(body: &[u8], max: usize) {
    let _ = decode_frame::<T>(body, max);
    let _ = bincode::deserialize::<T>(body);
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 12 {
        0 => decode::<JoinRequest>(body, MAX_CONTROL_FRAME),
        1 => decode::<JoinAccept>(body, MAX_CONTROL_FRAME),
        2 => decode::<PlayTicket>(body, MAX_CONTROL_FRAME),
        3 => decode::<ClientHello>(body, MAX_CONTROL_FRAME),
        4 => decode::<ServerHello>(body, MAX_CONTROL_FRAME),
        5 => decode::<ClientToGs>(body, MAX_CONTROL_FRAME),
        6 => decode::<GsToClient>(body, MAX_SNAPSHOT_FRAME),
        7 => decode::<Heartbeat>(body, MAX_CONTROL_FRAME),
        8 => decode::<TranscriptDigest>(body, MAX_TRANSCRIPT_FRAME),
        9 => decode::<ProtectedReceipt>(body, MAX_CONTROL_FRAME),
        10 => decode::<TpmQuote>(body, MAX_CONTROL_FRAME),
        _ => decode::<ClientInput>(body, MAX_CONTROL_FRAME),
    }
});
