use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Unified signature type: ed25519 signature bytes (64 bytes).
/// Some sigs are still Vec<u8> (e.g. Heartbeat.sig_gs) and will eventually
/// become [u8;64] everywhere.
pub type Sig = Vec<u8>;

/// GS → VS during admission.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,

    /// Hash of the GS binary (attestation placeholder for now).
    pub sw_hash: [u8; 32],

    /// Wallclock time (ms since Unix epoch) when this was signed.
    pub t_unix_ms: u64,

    /// Anti-replay nonce.
    pub nonce: [u8; 16],

    /// Ephemeral per-session GS public key (Ed25519).
    pub ephemeral_pub: [u8; 32],

    /// Signature by GS long-term key over the canonical JoinRequest body.
    pub sig_gs: Sig,

    /// GS long-term public key (Ed25519).
    pub gs_pub: [u8; 32],
}

/// VS → GS after admitting it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    /// VS-minted session ID (random 16 bytes).
    pub session_id: [u8; 16],

    /// VS signature binding this session_id to the GS.
    pub sig_vs: Sig,

    /// VS long-term public key (Ed25519).
    pub vs_pub: [u8; 32],
}

/// VS → GS (and then GS → client).
/// This is "proof GS is currently blessed."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],

    /// Optional binding to a specific client pubkey.
    /// [0u8;32] means "any client".
    pub client_binding: [u8; 32],

    /// Monotonic counter (1,2,3,...) per session.
    pub counter: u64,

    /// Earliest ms timestamp this ticket is allowed to be used.
    pub not_before_ms: u64,

    /// Latest ms timestamp this ticket is allowed to be used.
    pub not_after_ms: u64,

    /// Hash(chain) of previous ticket body. Lets client/GS detect gaps or forks.
    pub prev_ticket_hash: [u8; 32],

    /// VS signature on the canonical tuple:
    /// (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
    #[serde(with = "BigArray")]
    pub sig_vs: [u8; 64],
}

/// GS → client as first message on the local TCP link.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerHello {
    pub session_id: [u8; 16],
    pub ticket: PlayTicket,
    pub vs_pub: [u8; 32],
}

/// Minimal set of player actions for now.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientCmd {
    Move { dx: f32, dy: f32 },
}

/// Client → GS input packet (one per "frame"/tick").
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInput {
    /// Which GS session this input is for.
    pub session_id: [u8; 16],

    /// Which PlayTicket this input is stapled to.
    pub ticket_counter: u64,

    /// Exact VS signature from that PlayTicket.
    /// (GS will check it matches the latest ticket it forwarded.)
    #[serde(with = "BigArray")]
    pub ticket_sig_vs: [u8; 64],

    /// Client-side strictly monotonic nonce (1,2,3,...).
    pub client_nonce: u64,

    /// The actual command (Move, etc.).
    pub cmd: ClientCmd,

    /// Client pubkey (Ed25519, 32 bytes) representing this player.
    pub client_pub: [u8; 32],

    /// Client signature (Ed25519, 64 bytes) over canonical tuple:
    /// (session_id, ticket_counter, ticket_sig_vs, client_nonce, cmd)
    #[serde(with = "BigArray")]
    pub client_sig: [u8; 64],
}

/// GS authoritative events that matter for transcript / audit / replay.
///
/// Each tick GS turns ClientInput into actual sim state ("here is where you
/// ended up", "who hit who for how much", etc.). We hash these events into
/// `receipt_tip` so GS can't rewrite history later.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthoritativeEvent {
    MoveResolved {
        who: [u8; 32],
        x: f32,
        y: f32,
        tick: u64,
    },
}

/// GS → client: snapshot of world state for rendering / HUD / etc.
///
/// This is what the future Vulkan/wgpu client will consume.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorldSnapshot {
    pub tick: u64,
    pub you: (f32, f32),
    pub others: Vec<([u8; 32], f32, f32)>,
}

/// GS → client: "Here's a fresher PlayTicket from VS, use this now."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TicketUpdate {
    pub ticket: PlayTicket,
}

/// Messages flowing Client -> GS over the local TCP link.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientToGs {
    Input(ClientInput),
}

/// Messages flowing GS -> Client over the local TCP link.
/// We mostly send raw structs today, but this enum is here for evolution.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GsToClient {
    ServerHello(ServerHello),
    WorldSnapshot(WorldSnapshot),
    TicketUpdate(TicketUpdate),
}

// -------------------------
// GS <-> VS runtime protocol
// -------------------------

/// GS → VS heartbeat (~2s).
/// Proves liveness and pushes the GS's current transcript tip.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],

    /// Monotonic GS counter (1,2,3,...). VS kills session if it stalls or regresses.
    pub gs_counter: u64,

    /// GS local time in ms (used for debug / replay forensics).
    pub gs_time_ms: u64,

    /// Rolling hash / commitment of all "accepted" events so far.
    pub receipt_tip: [u8; 32],

    /// Signature by GS's ephemeral session key over the canonical heartbeat bytes.
    pub sig_gs: Sig,
}

/// GS → VS: "Here's my current transcript digest at counter C."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TranscriptDigest {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub receipt_tip: [u8; 32],
}

/// VS → GS in response to TranscriptDigest.
/// VS signs what GS claimed so GS can't deny it later.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtectedReceipt {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub receipt_tip: [u8; 32],

    /// VS signature binding (session_id, gs_counter, receipt_tip).
    pub sig_vs: Sig,
}
