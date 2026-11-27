//! Every owned CBOR control-plane and simulation message a peer can send,
//! decoded exactly as the receive paths do.
#![no_main]

use fpp::control::{
    AttestChallenge, ChallengeRequest, CheckpointSubmit, ControlMsg, CredentialChallenge,
    CredentialResponse, EquivocationReport, EvidenceAnswer, EvidenceRequest, EvidenceStoreRequest,
    EvidenceStoreResponse, GossipAnswer, GossipRequest, JoinAccept, JoinRequest, LogRequest,
    LogResponse, MatchAnswer, MatchRequest, PlaceResponse, ReportAnswer, RevocationRequest,
    RevocationResponse, ToGameServer,
};
use fpp_sim::game_wire::{ClientCmd, WorldSnapshot};
use libfuzzer_sys::fuzz_target;

fn decode<T: ControlMsg>(body: &[u8]) {
    if let Ok(msg) = T::decode_cbor(body) {
        let re = msg.encode_cbor();
        assert_eq!(re, body);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 25 {
        0 => decode::<JoinRequest>(body),
        1 => decode::<JoinAccept>(body),
        2 => decode::<ChallengeRequest>(body),
        3 => decode::<AttestChallenge>(body),
        4 => decode::<ToGameServer>(body),
        5 => decode::<CheckpointSubmit>(body),
        6 => decode::<EvidenceRequest>(body),
        7 => decode::<EvidenceAnswer>(body),
        8 => decode::<MatchRequest>(body),
        9 => decode::<MatchAnswer>(body),
        10 => {
            let _ = ClientCmd::decode(body);
        }
        11 => {
            let _ = WorldSnapshot::decode(body);
        }
        12 => decode::<CredentialChallenge>(body),
        13 => decode::<GossipRequest>(body),
        14 => decode::<GossipAnswer>(body),
        15 => decode::<EquivocationReport>(body),
        16 => decode::<ReportAnswer>(body),
        17 => decode::<CredentialResponse>(body),
        18 => decode::<PlaceResponse>(body),
        19 => decode::<RevocationRequest>(body),
        20 => decode::<RevocationResponse>(body),
        21 => decode::<EvidenceStoreRequest>(body),
        22 => decode::<EvidenceStoreResponse>(body),
        23 => decode::<LogRequest>(body),
        _ => decode::<LogResponse>(body),
    }
});
