//! GS side of VS admission.

use anyhow::{bail, Result};
use common::{
    crypto::{sigvec_to_array64, verify},
    proto::JoinAccept,
};
use ed25519_dalek::VerifyingKey;

/// Accept a `JoinAccept` only if it was signed by the pinned VS key.
///
/// The `vs_pub` carried in the message is never trusted on its own: a
/// fake VS (or a MITM) would simply send its own key.
pub fn verify_join_accept(pinned_vs: &VerifyingKey, ja: &JoinAccept) -> Result<()> {
    if ja.vs_pub != pinned_vs.to_bytes() {
        bail!(
            "JoinAccept from untrusted VS key {} (pinned {})",
            hex::encode(ja.vs_pub),
            hex::encode(pinned_vs.to_bytes())
        );
    }
    let Some(sig) = sigvec_to_array64(&ja.sig_vs) else {
        bail!("JoinAccept sig_vs length {} != 64", ja.sig_vs.len());
    };
    if !verify(pinned_vs, &ja.session_id, &sig) {
        bail!("JoinAccept signature invalid");
    }
    Ok(())
}
