// crates/client-bevy/src/lib.rs

use bevy::input::{keyboard::KeyCode, ButtonInput};
use common::proto::{ClientCmd, WorldSnapshot};

/// Max per-tick move magnitude (mirrors GS side).
pub const MAX_STEP: f32 = 1.0;

/// Clamp a requested move to length <= MAX_STEP.
#[inline]
pub fn clamp_move(mut dx: f32, mut dy: f32) -> (f32, f32) {
    let mag2 = dx * dx + dy * dy;
    if mag2 > MAX_STEP * MAX_STEP {
        let mag = mag2.sqrt();
        if mag > 0.0 {
            let s = MAX_STEP / mag;
            dx *= s;
            dy *= s;
        }
    }
    (dx, dy)
}

/// Read keyboard state → optional clamped `ClientCmd::Move`.
/// Supports both WASD and Arrow keys.
pub fn gather_input_impl(keys: &ButtonInput<KeyCode>) -> Option<ClientCmd> {
    let mut dx = 0.0f32;
    let mut dy = 0.0f32;

    // Bevy 0.17 key names
    if keys.pressed(KeyCode::KeyW) || keys.pressed(KeyCode::ArrowUp) {
        dy += 1.0;
    }
    if keys.pressed(KeyCode::KeyS) || keys.pressed(KeyCode::ArrowDown) {
        dy -= 1.0;
    }
    if keys.pressed(KeyCode::KeyA) || keys.pressed(KeyCode::ArrowLeft) {
        dx -= 1.0;
    }
    if keys.pressed(KeyCode::KeyD) || keys.pressed(KeyCode::ArrowRight) {
        dx += 1.0;
    }

    if dx != 0.0 || dy != 0.0 {
        // normalize so diagonals aren't faster
        let len = (dx * dx + dy * dy).sqrt();
        Some(ClientCmd::Move {
            dx: (dx / len) as f32,
            dy: (dy / len) as f32,
        })
    } else {
        None
    }
}

/// Drain queued snapshots without awaiting, returning everything available now.
pub fn pump_snapshots_impl(
    rx: &mut tokio::sync::mpsc::Receiver<WorldSnapshot>,
) -> Vec<WorldSnapshot> {
    let mut out = Vec::new();
    while let Ok(ws) = rx.try_recv() {
        out.push(ws);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_limits_length() {
        let (dx, dy) = clamp_move(10.0, 0.0);
        assert!((dx - MAX_STEP).abs() < 1e-6 && dy == 0.0);

        let (dx, dy) = clamp_move(1.0, 1.0);
        let len = (dx * dx + dy * dy).sqrt();
        assert!(len <= MAX_STEP + 1e-6);
    }
}
