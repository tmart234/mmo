//! Entry formats with a meaning to more than one party: the writer that
//! appends them and the relying parties that look them up.
//!
//! - **Checkpoint leaf** (EVD-02): Server Liveness appends one for every
//!   game-server Checkpoint it verified: `"fpp/1/checkpoint-leaf\0" ‖
//!   match_id (16) ‖ u32le(epoch) ‖ SHA-256 of the signed Checkpoint (32)`.
//!   A player holding a Checkpoint for the same match and epoch with
//!   another digest holds proof that the server showed it something else
//!   (a split view, EVD-03).
//! - **Equivocation leaf**: Server Liveness records a proven split view
//!   before it revokes: `"fpp/1/equivocation\0" ‖ match_id ‖ u32le(epoch) ‖
//!   logged digest ‖ reported digest`.

pub const CHECKPOINT: &[u8] = b"fpp/1/checkpoint-leaf\0";
pub const EQUIVOCATION: &[u8] = b"fpp/1/equivocation\0";

/// A checkpoint leaf.
pub fn checkpoint(match_id: &[u8; 16], epoch: u32, digest: &[u8; 32]) -> Vec<u8> {
    let mut v = CHECKPOINT.to_vec();
    v.extend_from_slice(match_id);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(digest);
    v
}

/// (match_id, epoch, digest) of a checkpoint leaf.
pub fn parse_checkpoint(entry: &[u8]) -> Option<([u8; 16], u32, [u8; 32])> {
    let rest = entry.strip_prefix(CHECKPOINT)?;
    if rest.len() != 16 + 4 + 32 {
        return None;
    }
    Some((
        rest[..16].try_into().ok()?,
        u32::from_le_bytes(rest[16..20].try_into().ok()?),
        rest[20..].try_into().ok()?,
    ))
}

/// An equivocation leaf.
pub fn equivocation(
    match_id: &[u8; 16],
    epoch: u32,
    logged: &[u8; 32],
    reported: &[u8; 32],
) -> Vec<u8> {
    let mut v = EQUIVOCATION.to_vec();
    v.extend_from_slice(match_id);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(logged);
    v.extend_from_slice(reported);
    v
}

#[cfg(test)]
mod tests {
    #[test]
    fn checkpoint_leaves_round_trip() {
        let leaf = super::checkpoint(&[1; 16], 7, &[2; 32]);
        assert_eq!(super::parse_checkpoint(&leaf), Some(([1; 16], 7, [2; 32])));
        assert_eq!(super::parse_checkpoint(&leaf[..leaf.len() - 1]), None);
        assert_eq!(
            super::parse_checkpoint(&super::equivocation(&[1; 16], 7, &[2; 32], &[3; 32])),
            None
        );
    }
}
