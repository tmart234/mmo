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
