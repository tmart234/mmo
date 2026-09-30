//! Requests between the services of a cell.

/// Server Liveness, as the Broker calls it: which admitted game servers
/// can take players now.
pub mod liveness {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum Request {
        /// Reserve a player slot on a game server that is blessed (SARs
        /// flowing) and has checkpointed.
        Place,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum Response {
        Placed(Placement),
        /// No game server can take a player.
        NoServer,
        Refused(String),
    }

    /// A reserved slot on a game server: what the Broker puts in the SAT
    /// and tells the client.
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub struct Placement {
        pub match_id: [u8; 16],
        /// The instance key its SARs certify (SAT `aud` is its digest).
        pub instance_pub: [u8; 32],
        pub noise_static: [u8; 32],
        pub game_addr: String,
        pub slot: u16,
    }
}

/// The Revocation Feed (04 §9): Enforcement publishes signed
/// `RevocationEvent`s; Brokers and Server Liveness follow them.
pub mod revocation {
    use serde::{Deserialize, Serialize};

    /// The longest a `Since` request waits for new events.
    pub const MAX_WAIT_MS: u64 = 30_000;

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum Request {
        /// A signed `RevocationEvent` (COSE_Sign1 by the Enforcement key).
        /// Publishers only.
        Publish(Vec<u8>),
        /// Events from sequence number `from` on, waiting up to `wait_ms`
        /// (at most [`MAX_WAIT_MS`]) for one if there is none yet.
        /// Subscribers only.
        Since { from: u64, wait_ms: u64 },
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum Response {
        /// Its sequence number in the feed, and its index in the
        /// Transparency Log (when the feed logs).
        Published {
            seq: u64,
            log_index: Option<u64>,
        },
        /// (sequence number, signed event), in order.
        Events(Vec<(u64, Vec<u8>)>),
        Refused(String),
    }
}

/// The Evidence Store: content-addressed objects (SHA-256 of their bytes),
/// indexed by match. Server Liveness stores the Checkpoints it verified;
/// auditors read them back.
pub mod evidence {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum Request {
        /// Store `object` under its digest, listed under `match_id`.
        /// Writers only.
        Put { match_id: [u8; 16], object: Vec<u8> },
        /// Readers only.
        Get([u8; 32]),
        /// Digests stored under a match, in the order stored. Readers only.
        List([u8; 16]),
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum Response {
        Stored([u8; 32]),
        Object(Option<Vec<u8>>),
        Digests(Vec<[u8; 32]>),
        Refused(String),
    }
}
