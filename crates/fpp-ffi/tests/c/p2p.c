/* C test for the SDK's secure P2P session (milestone M2), using nothing but
 * fpp.h. One host and two joiners exchange datagrams in memory (the "network"
 * is a function that routes queued packets by address), the way a game's
 * glue drives the SDK from its own UDP socket. Checks the attacks behind
 * Halo: CE findings H03 and H04: an invite holder cannot read or forge
 * another player's traffic, and replayed packets are dropped.
 * Exit status is the number of failed checks. Built for x86_64 and i686.
 */
#include <stdio.h>
#include <string.h>

#include "fpp.h"

static int failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                    \
        }                                                                  \
    } while (0)

#define CHECK_STATUS(expr, want)                                                         \
    do {                                                                                 \
        FppStatus got_ = (expr);                                                         \
        if (got_ != (want)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s -> %d (%s), want %d\n", __FILE__, __LINE__,  \
                    #expr, (int)got_, fpp_status_str((int)got_), (int)(want));           \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

/* Opaque addresses: the game would use a struct sockaddr_in. */
static const uint8_t HOST_ADDR[] = "host:2302";
static const uint8_t ALICE_ADDR[] = "alice:2303";
static const uint8_t MALLORY_ADDR[] = "mallory:2304";

typedef struct {
    uint8_t to[FPP_P2P_MAX_ADDRESS];
    size_t to_len;
    uint8_t packet[FPP_P2P_MAX_PACKET];
    size_t len;
} Datagram;

/* Everything that crossed the wire, for the attacker to replay. */
enum { LOG_MAX = 64 };
static Datagram wire_log[LOG_MAX];
static int wire_n = 0;

static void log_datagram(const Datagram *d) {
    if (wire_n < LOG_MAX) wire_log[wire_n++] = *d;
}

static int same(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    return a_len == b_len && memcmp(a, b, a_len) == 0;
}

/* Route every queued datagram until all endpoints are quiet. */
static void pump(FppP2pHost *host, FppP2pJoiner *j, const uint8_t *j_addr, size_t j_addr_len) {
    int moved = 1;
    while (moved) {
        Datagram d;
        moved = 0;
        while (fpp_p2p_joiner_poll_transmit(j, d.to, sizeof d.to, &d.to_len, d.packet,
                                            sizeof d.packet, &d.len) == FPP_STATUS_OK) {
            moved = 1;
            log_datagram(&d);
            if (same(d.to, d.to_len, HOST_ADDR, sizeof HOST_ADDR))
                (void)fpp_p2p_host_recv(host, j_addr, j_addr_len, d.packet, d.len);
        }
        while (fpp_p2p_host_poll_transmit(host, d.to, sizeof d.to, &d.to_len, d.packet,
                                          sizeof d.packet, &d.len) == FPP_STATUS_OK) {
            moved = 1;
            log_datagram(&d);
            if (same(d.to, d.to_len, j_addr, j_addr_len))
                (void)fpp_p2p_joiner_recv(j, HOST_ADDR, sizeof HOST_ADDR, d.packet, d.len);
        }
    }
}

static FppSigner *signer_from_byte(uint8_t b) {
    uint8_t seed[32];
    FppSigner *s = NULL;
    memset(seed, b, sizeof seed);
    CHECK_STATUS(fpp_signer_from_seed(seed, &s), FPP_STATUS_OK);
    return s;
}

int main(void) {
    uint8_t host_priv[32], host_pub[32], again[32], invite[32], instance_pub[32];
    uint8_t data[FPP_P2P_MAX_PACKET];
    const uint8_t host_hello[] = "slayer/bloodgulch";
    const uint8_t attestation[] = "AR:cwt-bytes";
    FppSigner *instance = signer_from_byte(0x61);
    FppSigner *alice_key = signer_from_byte(0x51), *mallory_key = signer_from_byte(0x66);
    uint8_t alice_pub[32];
    FppP2pHost *host = NULL;
    FppP2pJoiner *alice = NULL, *mallory = NULL;
    FppP2pEvent ev;
    uint32_t alice_peer = 0, count = 0;
    int i;

    memset(invite, 0x07, sizeof invite);
    CHECK_STATUS(fpp_p2p_keypair_generate(host_priv, host_pub), FPP_STATUS_OK);
    CHECK_STATUS(fpp_p2p_public_key(host_priv, again), FPP_STATUS_OK);
    CHECK(memcmp(host_pub, again, 32) == 0);
    CHECK_STATUS(fpp_signer_public_key(instance, instance_pub), FPP_STATUS_OK);
    CHECK_STATUS(fpp_signer_public_key(alice_key, alice_pub), FPP_STATUS_OK);

    CHECK_STATUS(fpp_p2p_host_new(host_priv, invite, instance_pub, host_hello, sizeof host_hello,
                                  16, &host),
                 FPP_STATUS_OK);
    CHECK_STATUS(fpp_p2p_host_poll_event(host, &ev, data, sizeof data), FPP_STATUS_EMPTY);

    /* Mallory holds the invite and joins normally. */
    CHECK_STATUS(fpp_p2p_joiner_new(host_pub, invite, mallory_key, NULL, 0, NULL, 0, HOST_ADDR,
                                    sizeof HOST_ADDR, &mallory),
                 FPP_STATUS_OK);
    pump(host, mallory, MALLORY_ADDR, sizeof MALLORY_ADDR);
    CHECK_STATUS(fpp_p2p_host_poll_event(host, &ev, data, sizeof data), FPP_STATUS_OK);
    CHECK(ev.kind == FPP_P2P_EVENT_KIND_PEER_JOINED && ev.attestation_len == 0);
    CHECK_STATUS(fpp_p2p_joiner_poll_event(mallory, &ev, data, sizeof data), FPP_STATUS_OK);
    CHECK(ev.kind == FPP_P2P_EVENT_KIND_CONNECTED);

    /* Alice joins with an Attestation Result attached. */
    wire_n = 0;
    CHECK_STATUS(fpp_p2p_joiner_new(host_pub, invite, alice_key, attestation, sizeof attestation,
                                    (const uint8_t *)"alice", 5, HOST_ADDR, sizeof HOST_ADDR,
                                    &alice),
                 FPP_STATUS_OK);
    CHECK_STATUS(fpp_p2p_joiner_send(alice, (const uint8_t *)"x", 1), FPP_STATUS_P2P_STATE);
    pump(host, alice, ALICE_ADDR, sizeof ALICE_ADDR);

    /* A too-small buffer reports the size and keeps the event queued. */
    CHECK_STATUS(fpp_p2p_host_poll_event(host, &ev, data, 4), FPP_STATUS_BUFFER_TOO_SMALL);
    CHECK(ev.data_len > 4);
    CHECK_STATUS(fpp_p2p_host_poll_event(host, &ev, data, sizeof data), FPP_STATUS_OK);
    CHECK(ev.kind == FPP_P2P_EVENT_KIND_PEER_JOINED);
    CHECK(ev.has_key && memcmp(ev.key, alice_pub, 32) == 0);
    CHECK(ev.attestation_len == sizeof attestation &&
          memcmp(data, attestation, sizeof attestation) == 0);
    CHECK(ev.data_len == ev.attestation_len + ev.admit_pop_len + 5 &&
          memcmp(data + ev.attestation_len + ev.admit_pop_len, "alice", 5) == 0);
    alice_peer = ev.peer;
    CHECK_STATUS(fpp_p2p_host_peer_count(host, &count), FPP_STATUS_OK);
    CHECK(count == 2);

    CHECK_STATUS(fpp_p2p_joiner_poll_event(alice, &ev, data, sizeof data), FPP_STATUS_OK);
    CHECK(ev.kind == FPP_P2P_EVENT_KIND_CONNECTED);
    CHECK(ev.has_key && memcmp(ev.key, instance_pub, 32) == 0);
    CHECK(ev.data_len == sizeof host_hello && memcmp(data, host_hello, sizeof host_hello) == 0);

    /* Game traffic both ways. */
    CHECK_STATUS(fpp_p2p_joiner_send(alice, (const uint8_t *)"flank left", 10), FPP_STATUS_OK);
    CHECK_STATUS(fpp_p2p_host_send(host, alice_peer, (const uint8_t *)"state", 5), FPP_STATUS_OK);
    pump(host, alice, ALICE_ADDR, sizeof ALICE_ADDR);
    CHECK_STATUS(fpp_p2p_host_poll_event(host, &ev, data, sizeof data), FPP_STATUS_OK);
    CHECK(ev.kind == FPP_P2P_EVENT_KIND_DATA && ev.peer == alice_peer && ev.data_len == 10 &&
          memcmp(data, "flank left", 10) == 0);
    CHECK_STATUS(fpp_p2p_joiner_poll_event(alice, &ev, data, sizeof data), FPP_STATUS_OK);
    CHECK(ev.kind == FPP_P2P_EVENT_KIND_DATA && ev.data_len == 5);

    /* H03: nothing Alice's session carried opens under Mallory's session,
     * and the plaintext never appears on the wire. */
    for (i = 0; i < wire_n; i++) {
        size_t k;
        CHECK(fpp_p2p_joiner_recv(mallory, HOST_ADDR, sizeof HOST_ADDR, wire_log[i].packet,
                                  wire_log[i].len) != FPP_STATUS_OK);
        for (k = 0; k + 5 <= wire_log[i].len; k++) CHECK(memcmp(wire_log[i].packet + k, "flank", 5) != 0);
    }
    CHECK_STATUS(fpp_p2p_joiner_poll_event(mallory, &ev, data, sizeof data), FPP_STATUS_EMPTY);

    /* H04: Alice's last datagram to the host, replayed, is dropped; forged, it fails. */
    for (i = wire_n - 1; i >= 0; i--) {
        if (same(wire_log[i].to, wire_log[i].to_len, HOST_ADDR, sizeof HOST_ADDR)) break;
    }
    CHECK(i >= 0);
    if (i >= 0) {
        Datagram d = wire_log[i];
        CHECK_STATUS(fpp_p2p_host_recv(host, ALICE_ADDR, sizeof ALICE_ADDR, d.packet, d.len),
                     FPP_STATUS_P2P_REPLAY);
        d.packet[5] ^= 0x40; /* a fresh counter: only authentication can stop it now */
        CHECK_STATUS(fpp_p2p_host_recv(host, MALLORY_ADDR, sizeof MALLORY_ADDR, d.packet, d.len),
                     FPP_STATUS_P2P_DECRYPT);
    }
    CHECK_STATUS(fpp_p2p_host_poll_event(host, &ev, data, sizeof data), FPP_STATUS_EMPTY);

    /* The host refuses a player (e.g. its attestation is below the lobby's tier). */
    CHECK_STATUS(fpp_p2p_host_disconnect(host, alice_peer, 5), FPP_STATUS_OK);
    pump(host, alice, ALICE_ADDR, sizeof ALICE_ADDR);
    CHECK_STATUS(fpp_p2p_joiner_poll_event(alice, &ev, data, sizeof data), FPP_STATUS_OK);
    CHECK(ev.kind == FPP_P2P_EVENT_KIND_CLOSED && ev.reason == 5);
    CHECK_STATUS(fpp_p2p_host_send(host, alice_peer, data, 1), FPP_STATUS_P2P_UNKNOWN_PEER);

    /* Argument checks. */
    CHECK_STATUS(fpp_p2p_host_recv(host, NULL, 0, data, 1), FPP_STATUS_INVALID_ARGUMENT);
    CHECK_STATUS(fpp_p2p_host_recv(host, ALICE_ADDR, sizeof ALICE_ADDR, data, 3),
                 FPP_STATUS_P2P_MALFORMED);
    CHECK_STATUS(fpp_p2p_joiner_new(NULL, invite, alice_key, NULL, 0, NULL, 0, HOST_ADDR,
                                    sizeof HOST_ADDR, &alice),
                 FPP_STATUS_NULL_POINTER);

    fpp_p2p_joiner_free(alice);
    fpp_p2p_joiner_free(mallory);
    fpp_p2p_host_free(host);
    fpp_signer_free(instance);
    fpp_signer_free(alice_key);
    fpp_signer_free(mallory_key);
    fpp_p2p_host_free(NULL);
    if (failures == 0) printf("fpp-p2p: all checks passed\n");
    return failures;
}
