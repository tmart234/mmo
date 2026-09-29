//! F07: frame lengths are checked against a cap before any allocation.

use common::framing::{decode_frame, frame_len, MAX_CONTROL_FRAME, MAX_TRANSCRIPT_FRAME};
use common::proto::ClientHello;

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

#[test]
fn rejects_length_prefix_over_cap() {
    // The old VS bi-stream path allocated whatever a peer declared (up to 4 GiB).
    assert!(frame_len(u32::MAX.to_le_bytes(), MAX_TRANSCRIPT_FRAME).is_err());
    let just_over = (MAX_CONTROL_FRAME as u32 + 1).to_le_bytes();
    assert!(frame_len(just_over, MAX_CONTROL_FRAME).is_err());
    assert_eq!(
        frame_len((MAX_CONTROL_FRAME as u32).to_le_bytes(), MAX_CONTROL_FRAME).unwrap(),
        MAX_CONTROL_FRAME
    );
}

#[test]
fn decodes_valid_frame() {
    let hello = ClientHello::new([7; 32]);
    let buf = frame(&bincode::serialize(&hello).unwrap());
    let back: ClientHello = decode_frame(&buf, MAX_CONTROL_FRAME).unwrap();
    assert_eq!(back.client_pub, [7; 32]);
}

#[test]
fn rejects_truncated_and_oversized_frames() {
    assert!(decode_frame::<ClientHello>(&[1, 0], MAX_CONTROL_FRAME).is_err());
    let mut buf = frame(&bincode::serialize(&ClientHello::new([7; 32])).unwrap());
    buf.truncate(buf.len() - 1);
    assert!(decode_frame::<ClientHello>(&buf, MAX_CONTROL_FRAME).is_err());
    let huge = (u32::MAX).to_le_bytes();
    assert!(decode_frame::<ClientHello>(&huge, MAX_CONTROL_FRAME).is_err());
}
