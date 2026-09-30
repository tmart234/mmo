//! Server Liveness's cell API: the Broker asks for a player slot on a game
//! server that is blessed and has checkpointed. Only the Broker may ask.

use fpp_svc::api::liveness::{Placement, Request, Response};
use fpp_svc::Caller;

use crate::ctx::Ctx;

/// Answer one request from `caller`.
pub fn handle(ctx: &Ctx, callers: &[String], caller: &Caller, request: Request) -> Response {
    if !caller.is(callers) {
        return Response::Refused(format!("{} may not place players", caller.0));
    }
    match request {
        Request::Place => ctx
            .sessions
            .iter_mut()
            .find(|s| !s.revoked && s.last_checkpoint.is_some())
            .map(|mut s| {
                let slot = s.next_slot;
                s.next_slot = s.next_slot.wrapping_add(1);
                Response::Placed(Placement {
                    match_id: *s.key(),
                    instance_pub: s.instance_pub,
                    noise_static: s.noise_static,
                    game_addr: s.game_addr.clone(),
                    slot,
                })
            })
            .unwrap_or(Response::NoServer),
    }
}

/// Serve the cell API on `endpoint` (mutual TLS) until it closes.
pub async fn serve(endpoint: fpp_svc::quinn::Endpoint, ctx: Ctx, callers: Vec<String>) {
    fpp_svc::serve(endpoint, move |caller: Caller, request: Request| {
        let response = handle(&ctx, &callers, &caller, request);
        async move { response }
    })
    .await
}
