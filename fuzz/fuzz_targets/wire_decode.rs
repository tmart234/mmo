//! Every control-link message a peer can send, decoded exactly as the
//! receive paths do.
#![no_main]

use common::framing::{decode_frame, MAX_CONTROL_FRAME};
use common::proto::{
    AttestChallenge, ChallengeRequest, CheckpointSubmit, ClientCmd, CredentialChallenge,
    CredentialResponse, EvidenceAnswer, EvidenceRequest, JoinAccept, JoinRequest, MatchAnswer,
    MatchRequest, SarIssue, WorldSnapshot,
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
    match selector % 14 {
        0 => decode::<JoinRequest>(body),
        1 => decode::<JoinAccept>(body),
        2 => decode::<ChallengeRequest>(body),
        3 => decode::<AttestChallenge>(body),
        4 => decode::<SarIssue>(body),
        5 => decode::<CheckpointSubmit>(body),
        6 => decode::<EvidenceRequest>(body),
        7 => decode::<EvidenceAnswer>(body),
        8 => decode::<MatchRequest>(body),
        9 => decode::<MatchAnswer>(body),
        10 => decode::<ClientCmd>(body),
        11 => decode::<WorldSnapshot>(body),
        12 => decode::<CredentialChallenge>(body),
        _ => decode::<CredentialResponse>(body),
    }
});
