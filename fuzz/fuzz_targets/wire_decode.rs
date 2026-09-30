//! Every control-link message a peer can send, decoded exactly as the
//! receive paths do.
#![no_main]

use common::framing::{decode_frame, MAX_CONTROL_FRAME};
use common::proto::{
    AttestChallenge, ChallengeRequest, CheckpointSubmit, ClientAdmission, ClientAdmissionRequest,
    ClientCmd, CredentialChallenge, CredentialResponse, JoinAccept, JoinRequest, SarIssue,
    WorldSnapshot,
};
use libfuzzer_sys::fuzz_target;

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) {
    let _ = decode_frame::<T>(body, MAX_CONTROL_FRAME);
    let _ = bincode::deserialize::<T>(body);
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 12 {
        0 => decode::<JoinRequest>(body),
        1 => decode::<JoinAccept>(body),
        2 => decode::<ChallengeRequest>(body),
        3 => decode::<AttestChallenge>(body),
        4 => decode::<SarIssue>(body),
        5 => decode::<CheckpointSubmit>(body),
        6 => decode::<ClientAdmissionRequest>(body),
        7 => decode::<ClientAdmission>(body),
        8 => decode::<ClientCmd>(body),
        9 => decode::<WorldSnapshot>(body),
        10 => decode::<CredentialChallenge>(body),
        _ => decode::<CredentialResponse>(body),
    }
});
