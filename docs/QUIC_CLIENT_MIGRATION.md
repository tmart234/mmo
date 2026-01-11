# Client → GS QUIC Migration Plan

## Current State

**Architecture:**
- VS ↔ GS: **QUIC** (using quinn) ✅
- GS ↔ Client: **TCP** (TcpListener on port 50000) ❌

The current implementation uses TCP for client connections, which is suboptimal for an MMO because:
1. Higher latency due to TCP head-of-line blocking
2. No built-in 0-RTT handshake
3. Slower connection establishment
4. No native support for connection migration (mobile/WiFi switching)

## Target State

**All connections use QUIC:**
- VS ↔ GS: QUIC (already done)
- GS ↔ Client: **QUIC** (new)

## Benefits

1. **Lower Latency**: QUIC uses UDP and avoids head-of-line blocking
2. **0-RTT Resumption**: Clients can reconnect instantly
3. **Connection Migration**: Seamless handoff between networks
4. **Multiplexing**: Multiple streams without blocking
5. **Better Congestion Control**: BBR-style algorithms
6. **Unified Protocol**: Same framing logic for all connections

## Implementation Plan

### Phase 1: Server-Side Changes

#### 1.1 Update GS client_port.rs

**Before:**
```rust
let listener = TcpListener::bind("127.0.0.1:50000").await?;
let (mut socket, peer_addr) = listener.accept().await?;
```

**After:**
```rust
let server_config = quinn::ServerConfig::with_single_cert(certs, key)?;
let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:50000".parse()?)?;

while let Some(connecting) = endpoint.accept().await {
    let conn = connecting.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    // Use common::framing::{send_msg, recv_msg} instead of tcp_send_bin/recv_bin_tcp
}
```

#### 1.2 Replace TCP framing with QUIC framing

**Files to modify:**
- `crates/gs-sim/src/client_port.rs`: Replace `send_bin_tcp`/`recv_bin_tcp` with `framing::{send_msg, recv_msg}`
- `crates/common/src/tcp_framing.rs`: Mark as deprecated or remove

### Phase 2: Client-Side Changes

#### 2.1 Update client-core/src/lib.rs

**Before:**
```rust
let mut stream = TcpStream::connect("127.0.0.1:50000").await?;
tcp_send_msg(&mut stream, &msg).await?;
let response: ServerHello = tcp_recv_msg(&mut stream).await?;
```

**After:**
```rust
let client_config = configure_client_quic()?;
let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
let conn = endpoint.connect_with(client_config, "127.0.0.1:50000".parse()?, "localhost")?.await?;
let (mut send, mut recv) = conn.open_bi().await?;
send_msg(&mut send, &msg).await?;
let response: ServerHello = recv_msg(&mut recv).await?;
```

#### 2.2 Update client-sim and client-bevy

**Files to modify:**
- `crates/client-core/src/bin/client_sim.rs`
- `crates/client-bevy/src/main.rs`
- `crates/tools/src/play.rs`
- `crates/tools/src/smoke.rs`

### Phase 3: Configuration & Certificates

#### 3.1 Client Certificate Generation

Unlike VS↔GS (which uses long-term identities), clients may use:
- Self-signed certificates (for testing)
- Anonymous QUIC (insecure_skip_verify for local dev)
- Production: Proper cert validation

#### 3.2 GS QUIC Server Configuration

```rust
fn configure_gs_quic_server() -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();

    let cert_chain = vec![rustls::Certificate(cert_der)];
    let key_der = rustls::PrivateKey(priv_key);

    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key_der)?;

    // Performance tuning
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(100_u32.into());
    transport_config.max_concurrent_uni_streams(100_u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    server_config.transport = Arc::new(transport_config);
    Ok(server_config)
}
```

### Phase 4: Testing

#### 4.1 Unit Tests

- Update existing TCP tests to use QUIC
- Add QUIC-specific tests (connection migration, 0-RTT, etc.)

#### 4.2 Integration Tests

- Smoke test with QUIC client/server
- Load test with 100+ concurrent QUIC connections
- Network condition tests (packet loss, latency)

#### 4.3 Performance Benchmarks

Compare TCP vs QUIC:
- Connection establishment time
- Round-trip latency
- Throughput under packet loss
- Connection migration overhead

### Phase 5: Rollout

1. **Week 1**: Implement server-side QUIC support (backward compatible with TCP)
2. **Week 2**: Migrate clients to QUIC
3. **Week 3**: Testing and performance validation
4. **Week 4**: Remove TCP support, QUIC-only

## Performance Expectations

**Expected Improvements:**
- **Latency**: 10-30% reduction in p99 latency (no head-of-line blocking)
- **Throughput**: 20-40% improvement under packet loss
- **Connection Time**: 50% faster with 0-RTT resumption
- **Mobile**: Seamless handoff between WiFi/cellular

## Risks & Mitigations

### Risk 1: Firewall/NAT Issues
**Mitigation:** QUIC uses UDP which may be blocked. Provide TCP fallback during transition.

### Risk 2: CPU Overhead
**Mitigation:** QUIC crypto is computationally expensive. Use hardware AES-NI, tune pool sizes.

### Risk 3: Debugging Complexity
**Mitigation:** QUIC is harder to debug than TCP. Add comprehensive logging and metrics.

## File Checklist

### To Modify:
- [ ] `crates/gs-sim/src/client_port.rs` - Replace TcpListener with quinn::Endpoint
- [ ] `crates/client-core/src/lib.rs` - Replace TcpStream with quinn::Connection
- [ ] `crates/client-core/src/bin/client_sim.rs` - Update smoke test
- [ ] `crates/client-bevy/src/main.rs` - Update Bevy client
- [ ] `crates/tools/src/play.rs` - Update play tool
- [ ] `crates/tools/src/smoke.rs` - Update smoke test
- [ ] `crates/common/src/tcp_framing.rs` - Mark deprecated

### To Add:
- [ ] `crates/common/src/quic_config.rs` - Shared QUIC configuration
- [ ] `crates/gs-sim/tests/quic_client_test.rs` - QUIC client tests

### To Update:
- [ ] `Cargo.toml` - Ensure quinn dependency is used by all crates
- [ ] `README.md` - Document QUIC usage
- [ ] `Makefile` - Update test targets

## References

- [QUIC RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
- [quinn Documentation](https://docs.rs/quinn/)
- [QUIC vs TCP Performance](https://blog.cloudflare.com/the-road-to-quic/)
