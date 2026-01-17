use bevy::diagnostic::{FrameTimeDiagnosticsPlugin, LogDiagnosticsPlugin};
use bevy::input::{keyboard::KeyCode, ButtonInput};
use bevy::prelude::*;
use bevy::time::{Fixed, Timer, TimerMode};

// Linear/sRGB conversions (0.17)
use bevy::color::Srgba;

// Gizmos
use bevy::prelude::Gizmos;

// Simple tonemapping to avoid LUT issues
use bevy::core_pipeline::tonemapping::Tonemapping;

use client_bevy::{gather_input_impl, pump_snapshots_impl};
use client_core::{connect_and_handshake_with_retry, recv_world, send_input};
use common::framing::send_msg_continue;
use common::proto::{ClientCmd, ClientToGs, WorldSnapshot};
use std::{sync::Mutex, time::Duration};
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

// Bevy 0.17 mesh primitives
use bevy::math::primitives::{Cuboid, Plane3d, Sphere};

const TICK_MS: u64 = 100; // 10 Hz client net loop

/// 0.17+: buffered messages
#[derive(Message)]
pub struct WorldSnapshotEvent(pub WorldSnapshot);

/// Net resources
#[derive(Resource)]
struct Net {
    tx_cmd: mpsc::Sender<ClientCmd>,
    rx_ws: Mutex<mpsc::Receiver<WorldSnapshot>>,
}

/// Marker for local player
#[derive(Component)]
struct You;

/// Marker for the giant unlit debug cube
#[derive(Component)]
struct DebugCube;

#[derive(Resource)]
struct DbgTicker(Timer);

fn setup_dbg(mut cmds: Commands) {
    cmds.insert_resource(DbgTicker(Timer::from_seconds(1.0, TimerMode::Repeating)));
}

fn main() {
    // (Harmless if a subscriber already exists)
    #[cfg(all(not(target_family = "wasm"), not(debug_assertions)))]
    let _ = tracing_subscriber::fmt::try_init();

    let sanity = std::env::args().any(|a| a == "--sanity");
    let mut app = App::new();

    app.add_plugins(DefaultPlugins)
        // Very bright ambient so PBR stuff is visible regardless of lights
        .insert_resource(AmbientLight {
            color: Color::WHITE,
            brightness: 2500.0,
            affects_lightmapped_meshes: true,
        })
        // Lighter background (linear) so silhouettes are obvious
        .insert_resource(ClearColor(Srgba::new(0.12, 0.14, 0.17, 1.0).into()))
        // Diagnostics in stdout
        .add_plugins(FrameTimeDiagnosticsPlugin::default())
        .add_plugins(LogDiagnosticsPlugin::default())
        // Fixed clock handy (GS runs at 20 Hz)
        .insert_resource(Time::<Fixed>::from_hz(20.0))
        .add_message::<WorldSnapshotEvent>()
        .add_systems(
            Startup,
            (
                setup_dbg,
                spawn_camera_3d,
                spawn_world,
                spawn_debug_ui,
                draw_axes_gizmos,
            ),
        );

    if !sanity {
        app.add_systems(Startup, net_startup).add_systems(
            Update,
            (
                gather_input_sys,   // sample keys each frame -> net thread
                pump_snapshots_sys, // flush snapshots from net thread
                apply_snapshots_sys,
            ),
        );
    }

    app.add_systems(Update, (dump_counts_sys, spin_debug_cube_sys));

    app.run();
}

fn spawn_camera_3d(mut commands: Commands) {
    // Camera looking at origin
    commands.spawn((
        Camera3d::default(),
        // Avoid LUT/pink/odd tonemapping states on fresh projects
        Tonemapping::None,
        Transform::from_xyz(0.0, 6.0, 12.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));

    // One strong directional light
    commands.spawn((
        DirectionalLight {
            shadows_enabled: false,
            illuminance: 30_000.0,
            ..Default::default()
        },
        Transform::from_xyz(8.0, 12.0, 8.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
}

// Spawn a floor, a small red (unlit) sphere, and a big yellow (unlit) cube
fn spawn_world(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    // Floor plane on XZ at origin
    let floor_mesh = meshes.add(Mesh::from(Plane3d::default()));
    let floor_mat = materials.add(StandardMaterial {
        base_color: Color::srgb(0.35, 0.37, 0.42),
        perceptual_roughness: 1.0,
        metallic: 0.0,
        ..Default::default()
    });
    commands.spawn((
        Mesh3d(floor_mesh),
        MeshMaterial3d(floor_mat),
        Transform::from_scale(Vec3::splat(60.0)),
    ));

    // Local player: small red sphere (UNLIT so it renders even if lighting is borked)
    let you_mesh = meshes.add(Mesh::from(Sphere { radius: 0.4 }));
    let you_mat = materials.add(StandardMaterial {
        base_color: Color::srgb(1.0, 0.25, 0.25),
        emissive: Srgba::new(0.10, 0.00, 0.00, 1.0).into(),
        unlit: true,
        ..Default::default()
    });
    commands.spawn((
        Mesh3d(you_mesh),
        MeshMaterial3d(you_mat),
        Transform::from_xyz(0.0, 0.4, 0.0),
        You,
    ));

    // GIANT UNLIT DEBUG CUBE near origin so it is impossible to miss
    let cube_mesh = meshes.add(Mesh::from(Cuboid::new(1.0, 1.0, 1.0)));
    let cube_mat = materials.add(StandardMaterial {
        base_color: Color::srgb(1.0, 1.0, 0.0),
        unlit: true,
        ..Default::default()
    });
    commands.spawn((
        Mesh3d(cube_mesh),
        MeshMaterial3d(cube_mat),
        Transform::from_xyz(0.0, 1.0, 0.0),
        DebugCube,
    ));
}

fn spawn_debug_ui(mut commands: Commands) {
    // Big banner so UI layer visibility is obvious
    commands
        .spawn((
            Node {
                width: Val::Percent(100.0),
                height: Val::Px(28.0),
                position_type: PositionType::Absolute,
                top: Val::Px(0.0),
                left: Val::Px(0.0),
                ..Default::default()
            },
            BackgroundColor(Srgba::new(0.0, 0.0, 0.0, 0.60).into()),
        ))
        .with_children(|p| {
            p.spawn((
                Text::new("WASD/Arrows to move — click the window to focus"),
                TextFont {
                    font_size: 18.0,
                    ..Default::default()
                },
                TextColor(Srgba::WHITE.into()),
                Node {
                    padding: UiRect::axes(Val::Px(10.0), Val::Px(4.0)),
                    ..Default::default()
                },
            ));
        });
}

/// Draw world axes with the correct 0.17 signature: (Transform, size)
fn draw_axes_gizmos(mut gizmos: Gizmos) {
    gizmos.axes(Transform::IDENTITY, 2.0);
}

fn dump_counts_sys(
    time: Res<Time>,
    mut tick: ResMut<DbgTicker>,
    q_cam: Query<Entity, With<Camera>>,
    q_mesh: Query<Entity, With<Mesh3d>>,
    q_you: Query<&Transform, With<You>>,
) {
    // Throttled to 1 Hz and demoted to DEBUG
    if tick.0.tick(time.delta()).just_finished() {
        let you = q_you.iter().next().map(|t| t.translation);
        bevy::log::debug!(
            target: "client",
            "dbg: cameras={} meshes={} you={:?}",
            q_cam.iter().len(),
            q_mesh.iter().len(),
            you
        );
    }
}

/// Slowly spin the debug cube so changes are visually obvious
fn spin_debug_cube_sys(mut q: Query<&mut Transform, With<DebugCube>>, time: Res<Time>) {
    if let Some(mut t) = q.iter_mut().next() {
        t.rotate_y(0.6 * time.delta_secs());
    }
}

fn net_startup(mut commands: Commands) {
    let (tx_cmd, mut rx_cmd) = mpsc::channel::<ClientCmd>(64);
    let (tx_ws, rx_ws) = mpsc::channel::<WorldSnapshot>(64);
    commands.insert_resource(Net {
        tx_cmd,
        rx_ws: Mutex::new(rx_ws),
    });

    let gs_addr = String::from("127.0.0.1:50000");

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async move {
            println!("[NET] connecting to {}...", gs_addr);

            let mut sess =
                match connect_and_handshake_with_retry(&gs_addr, 10, Duration::from_millis(200))
                    .await
                {
                    Ok(s) => {
                        println!(
                            "[NET] connected! session={}",
                            hex::encode(&s.session_id[..4])
                        );
                        s
                    }
                    Err(e) => {
                        eprintln!("[NET] failed to connect/handshake: {e:#}");
                        return;
                    }
                };

            let mut nonce: u64 = 1;
            let mut tick = interval(Duration::from_millis(TICK_MS));
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tick.tick().await;

                // Drain to most recent intent
                let mut latest: Option<ClientCmd> = None;
                while let Ok(cmd) = rx_cmd.try_recv() {
                    latest = Some(cmd);
                }

                // Always send something (prevents recv_world from stalling)
                let cmd = latest.unwrap_or(ClientCmd::Move { dx: 0.0, dy: 0.0 });
                if let Err(e) = send_input(&mut sess, nonce, cmd).await {
                    eprintln!("[NET] send_input failed: {e:#}");
                    break;
                }
                nonce = nonce.wrapping_add(1);

                match recv_world(&mut sess).await {
                    Ok(ws) => {
                        bevy::log::debug!(
                            target: "client",
                            "recv WorldSnapshot you=({:.2},{:.2}) tick={}",
                            ws.you.0,
                            ws.you.1,
                            ws.tick
                        );
                        let _ = tx_ws.try_send(ws);
                    }
                    Err(e) => {
                        eprintln!("[NET] recv_world failed: {e:#}");
                        break;
                    }
                }
            }

            // Graceful shutdown: send Bye over QUIC stream (not TCP!)
            println!("[NET] sending Bye...");
            let _ = send_msg_continue(&mut sess.send_stream, &ClientToGs::Bye).await;
            println!("[NET] disconnected.");
        });
    });
}

// --- Input / Net bridge systems (now in Update) ---

fn gather_input_sys(keys: Res<ButtonInput<KeyCode>>, net: Res<Net>) {
    if let Some(cmd) = gather_input_impl(&keys) {
        let _ = net.tx_cmd.try_send(cmd);
    }
}

fn pump_snapshots_sys(net: Res<Net>, mut writer: MessageWriter<WorldSnapshotEvent>) {
    let mut rx = net.rx_ws.lock().unwrap();
    for ws in pump_snapshots_impl(&mut rx) {
        writer.write(WorldSnapshotEvent(ws));
    }
}

fn apply_snapshots_sys(
    mut reader: MessageReader<WorldSnapshotEvent>,
    mut you_q: Query<&mut Transform, With<You>>,
) {
    for WorldSnapshotEvent(ws) in reader.read() {
        if let Some(mut t) = you_q.iter_mut().next() {
            t.translation.x = ws.you.0;
            t.translation.z = ws.you.1;
            t.translation.y = 0.4;
        }
    }
}
