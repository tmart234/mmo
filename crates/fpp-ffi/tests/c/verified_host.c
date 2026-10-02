/* A dedicated game server for a verified playlist (stage H5 of
 * docs/anticheat/08), written against nothing but fpp.h built with the
 * gs-link feature: the sequence a C game's dedicated host runs (the Halo
 * port's network.dedicated mode does the same).
 *
 * - Join Server Liveness (fpp_gs_link_connect) with an instance key that
 *   signs this run's Checkpoints and the static key of the fpp_p2p host the
 *   players dial; Server Liveness answers with the match and a SAR chain
 *   certifying both.
 * - Serve players over fpp_p2p_* on a UDP socket: send each joiner the
 *   current SAR (SarUpdate), admit it on Admit{SAT, AR} by the §7.2 checks
 *   (fpp_admission_admit), verify its InputCommits, relay every new SAR.
 * - Sign one Checkpoint per epoch (a second), submit it to Server Liveness
 *   and send it to every player (CheckpointHead).
 * - Apply the Revocation Feed's events, and the title's own device bans.
 *
 * Usage: fpp-verified-host <liveness ip:port> <ca.der> <bundle.json>
 *            <game ip:port> <seconds> [--client-build HEX] [--ban-after S]
 *            [--leave-after S]
 * --ban-after: ban the first admitted player's device S seconds after it was
 *   admitted (finding H08); --leave-after: S seconds after the second
 *   admission, close the link to Server Liveness but keep serving, as a
 *   server that lost its blessing and ignores it: its players must drop on
 *   their own when its SARs stop.
 * Prints one line per event ("host: ..."), for tools/src/verified_exit.rs.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "fpp.h"

enum { MAX_PLAYERS = 16, TICK_MS = 33, TICKS_PER_EPOCH = 30, MAX_TOKEN = 4096 };

struct player {
    int used;
    uint32_t peer;
    struct sockaddr_in address;
    uint8_t session_key[FPP_SESSION_KEY_MAX];
    size_t session_key_len;
    int admitted;
    uint16_t slot;
    uint8_t did[32];
    double admitted_at;
    int commits;
};

static struct player players[MAX_PLAYERS];
static FppP2pHost *host;
static int sock;
static uint8_t sar[MAX_TOKEN];
static size_t sar_len;
/* players admitted so far, and when the second was */
static int admissions;
static double second_admitted = -1;

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static uint64_t unix_s(void) { return (uint64_t)time(NULL); }

static int hex_decode(const char *text, uint8_t *out, size_t n) {
    size_t i;
    if (strlen(text) != 2 * n) return 0;
    for (i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(text + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

static void flush(void) {
    uint8_t to[FPP_P2P_MAX_ADDRESS], packet[FPP_P2P_MAX_PACKET];
    size_t to_len, len;
    while (fpp_p2p_host_poll_transmit(host, to, sizeof to, &to_len, packet, sizeof packet, &len) ==
           FPP_STATUS_OK) {
        if (to_len == sizeof(struct sockaddr_in))
            sendto(sock, packet, len, 0, (const struct sockaddr *)to, (socklen_t)to_len);
    }
}

/* encode with one of fpp_control_*, then send reliably */
static void send_message(uint32_t peer, const uint8_t *msg, size_t len) {
    FppStatus s = fpp_p2p_host_send_reliable(host, peer, msg, len);
    if (s != FPP_STATUS_OK) printf("host: send to peer %u failed (%s)\n", peer, fpp_status_str((int)s));
}

static void send_sar(uint32_t peer) {
    uint8_t msg[MAX_TOKEN + 64];
    size_t len;
    if (!sar_len) return;
    if (fpp_control_sar_update(sar, sar_len, msg, sizeof msg, &len) == FPP_STATUS_OK)
        send_message(peer, msg, len);
}

static struct player *player_of(uint32_t peer) {
    int i;
    for (i = 0; i < MAX_PLAYERS; i++)
        if (players[i].used && players[i].peer == peer) return &players[i];
    return NULL;
}

static void refuse(struct player *p, uint16_t code, int kick) {
    uint8_t msg[64];
    size_t len;
    if (fpp_control_refuse(code, (uint8_t)kick, msg, sizeof msg, &len) == FPP_STATUS_OK)
        send_message(p->peer, msg, len);
    fpp_p2p_host_tick(host, (uint64_t)(now_s() * 1000));
    flush();
    fpp_p2p_host_disconnect(host, p->peer, code);
    flush();
    p->used = 0;
}

static void on_admit(FppAdmission *admission, struct player *p, const uint8_t *data, const FppControl *c) {
    FppAdmitted a;
    uint8_t msg[64];
    size_t len;
    FppStatus s = fpp_admission_admit(admission, data, c->first_len, data + c->first_len, c->second_len,
                                      p->session_key, p->session_key_len, unix_s(), &a);
    if (s != FPP_STATUS_OK) {
        printf("host: refused peer %u: %s (reason %u: %s)\n", p->peer, fpp_status_str((int)s), a.reason,
               fpp_reason_str(a.reason));
        refuse(p, a.reason, 0);
        return;
    }
    p->admitted = 1;
    p->slot = a.slot;
    memcpy(p->did, a.did, 32);
    p->admitted_at = now_s();
    if (++admissions == 2) second_admitted = p->admitted_at;
    printf("host: admitted slot %u tier D%u platform %s queue %s\n", a.slot, a.tier, (const char *)a.platform,
           (const char *)a.queue);
    if (fpp_control_admitted(a.slot, 0, msg, sizeof msg, &len) == FPP_STATUS_OK) send_message(p->peer, msg, len);
}

static void on_message(FppAdmission *admission, struct player *p, const uint8_t *msg, size_t len) {
    FppControl c;
    static uint8_t data[2 * MAX_TOKEN];
    FppStatus s = fpp_control_decode(msg, len, &c, data, sizeof data);
    if (s != FPP_STATUS_OK) return;
    if (c.kind == FPP_CONTROL_KIND_ADMIT && !p->admitted) {
        on_admit(admission, p, data, &c);
    } else if (c.kind == FPP_CONTROL_KIND_INPUT_COMMIT && p->admitted) {
        FppInputCommitInfo info;
        if (fpp_verify_input_commit_key(data, c.first_len, p->session_key, p->session_key_len, &info) ==
                FPP_STATUS_OK &&
            info.slot == p->slot)
            p->commits++;
        else
            printf("host: slot %u sent an InputCommit that does not verify\n", p->slot);
    } else if (c.kind == FPP_CONTROL_KIND_BYE) {
        if (p->admitted) fpp_admission_remove(admission, p->slot);
        p->used = 0;
    }
}

static void poll_host(FppAdmission *admission) {
    FppP2pEvent ev;
    static uint8_t data[8192];
    while (fpp_p2p_host_poll_event(host, &ev, data, sizeof data) == FPP_STATUS_OK) {
        struct player *p = player_of(ev.peer);
        int i;
        switch (ev.kind) {
        case FPP_P2P_EVENT_KIND_PEER_JOINED:
            for (i = 0; i < MAX_PLAYERS && players[i].used; i++)
                ;
            if (i == MAX_PLAYERS) {
                fpp_p2p_host_disconnect(host, ev.peer, 13);
                break;
            }
            p = &players[i];
            memset(p, 0, sizeof *p);
            p->used = 1;
            p->peer = ev.peer;
            if (fpp_p2p_host_peer_session_key(host, ev.peer, p->session_key, &p->session_key_len) !=
                FPP_STATUS_OK) {
                p->used = 0;
                break;
            }
            printf("host: peer %u joined; sending the SAR\n", ev.peer);
            send_sar(ev.peer);
            break;
        case FPP_P2P_EVENT_KIND_MESSAGE:
            if (p) on_message(admission, p, data, ev.data_len);
            break;
        case FPP_P2P_EVENT_KIND_PEER_LEFT:
            if (p) {
                if (p->admitted) fpp_admission_remove(admission, p->slot);
                printf("host: slot %u left (%u)\n", p->slot, ev.reason);
                p->used = 0;
            }
            break;
        default:
            break;
        }
    }
    flush();
}

int main(int argc, char **argv) {
    FppGsLinkConfig config;
    FppGsLink *link = NULL;
    FppKeys *keys = NULL;
    FppSigner *instance = NULL;
    FppAdmission *admission = NULL;
    uint8_t static_private[32], static_public[32], instance_public[32], gs_seed[32], match_id[16];
    uint8_t build[32], prev[32];
    double seconds, ban_after = -1, leave_after = -1, start, next_tick;
    int have_build = 0, banned = 0, i;
    uint32_t tick = 0, epoch = 0;
    struct sockaddr_in bind_addr;
    char ip[64];
    unsigned port;
    FILE *random;

    if (argc < 6) {
        fprintf(stderr, "usage: %s liveness ca bundle game-addr seconds [options]\n", argv[0]);
        return 2;
    }
    /* (a line at a time: the test reads them as they come) */
    setvbuf(stdout, NULL, _IOLBF, 0);
    seconds = atof(argv[5]);
    for (i = 6; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--client-build"))
            have_build = hex_decode(argv[i + 1], build, 32);
        else if (!strcmp(argv[i], "--ban-after"))
            ban_after = atof(argv[i + 1]);
        else if (!strcmp(argv[i], "--leave-after"))
            leave_after = atof(argv[i + 1]);
    }
    random = fopen("/dev/urandom", "rb");
    if (!random || fread(gs_seed, 1, 32, random) != 32) return 2;
    fclose(random);

    /* the game port */
    if (sscanf(argv[4], "%63[^:]:%u", ip, &port) != 2) return 2;
    memset(&bind_addr, 0, sizeof bind_addr);
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &bind_addr.sin_addr);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0 || bind(sock, (struct sockaddr *)&bind_addr, sizeof bind_addr) != 0) {
        perror("bind");
        return 2;
    }
    {
        struct timeval tv = {0, 5000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }

    /* keys: the p2p host's static key, this run's instance key */
    if (fpp_p2p_keypair_generate(static_private, static_public) != FPP_STATUS_OK ||
        fpp_signer_generate(&instance) != FPP_STATUS_OK ||
        fpp_signer_public_key(instance, instance_public) != FPP_STATUS_OK ||
        fpp_keys_load_bundle(argv[3], &keys) != FPP_STATUS_OK) {
        fprintf(stderr, "host: keys\n");
        return 2;
    }

    /* join Server Liveness */
    memset(&config, 0, sizeof config);
    config.liveness = argv[1];
    config.ca_cert = argv[2];
    config.bundle = argv[3];
    config.gs_id = "verified-host";
    config.game_addr = argv[4];
    config.gs_key_seed = gs_seed;
    config.instance_public_key = instance_public;
    config.noise_public_key = static_public;
    config.sw_hash = NULL;
    config.tpm2 = 0;
    config.timeout_ms = 10000;
    if (fpp_gs_link_connect(&config, &link) != FPP_STATUS_OK) {
        fprintf(stderr, "host: cannot join Server Liveness\n");
        return 3;
    }
    fpp_gs_link_match_id(link, match_id);
    printf("host: joined; match %02x%02x%02x%02x..\n", match_id[0], match_id[1], match_id[2], match_id[3]);
    if (fpp_admission_new(keys, instance_public, match_id, 0, &admission) != FPP_STATUS_OK) return 2;
    if (have_build) fpp_admission_add_client_build(admission, build);
    if (fpp_p2p_host_new(static_private, NULL, instance_public, NULL, 0, MAX_PLAYERS, &host) != FPP_STATUS_OK)
        return 2;
    memset(prev, 0, sizeof prev);
    fflush(stdout);

    start = now_s();
    next_tick = start;
    while (now_s() - start < seconds) {
        uint8_t packet[2048];
        struct sockaddr_in from;
        socklen_t from_len = sizeof from;
        ssize_t n = recvfrom(sock, packet, sizeof packet, 0, (struct sockaddr *)&from, &from_len);
        FppGsEvent gev;
        static uint8_t gdata[MAX_TOKEN];

        if (n > 0) fpp_p2p_host_recv(host, (const uint8_t *)&from, sizeof from, packet, (size_t)n);
        poll_host(admission);

        /* Server Liveness: new SARs for every player, revocation events */
        while (link && fpp_gs_link_poll(link, &gev, gdata, sizeof gdata) == FPP_STATUS_OK) {
            if (gev.kind == FPP_GS_EVENT_KIND_SAR) {
                memcpy(sar, gdata, gev.data_len);
                sar_len = gev.data_len;
                for (i = 0; i < MAX_PLAYERS; i++)
                    if (players[i].used) send_sar(players[i].peer);
            } else if (gev.kind == FPP_GS_EVENT_KIND_REVOCATION) {
                FppRevocationOutcome outcome;
                if (fpp_admission_revocation(admission, gdata, gev.data_len, unix_s(), &outcome) == FPP_STATUS_OK)
                    printf("host: revocation event: outcome %d\n", (int)outcome);
            } else {
                printf("host: link to Server Liveness closed (%s)\n", fpp_reason_str(gev.reason));
                fpp_gs_link_free(link);
                link = NULL;
            }
        }
        if (link && leave_after >= 0 && second_admitted >= 0 && now_s() - second_admitted >= leave_after) {
            printf("host: leaving Server Liveness, still serving\n");
            fpp_gs_link_free(link);
            link = NULL;
        }

        /* H08: the title bans the first admitted player's device */
        if (!banned && ban_after >= 0) {
            for (i = 0; i < MAX_PLAYERS; i++) {
                if (players[i].used && players[i].admitted && now_s() - players[i].admitted_at >= ban_after) {
                    fpp_admission_ban_device(admission, players[i].did);
                    printf("host: banned the device of slot %u\n", players[i].slot);
                    banned = 1;
                    break;
                }
            }
        }
        {
            uint16_t slot, reason;
            while (fpp_admission_poll_removed(admission, &slot, &reason) == FPP_STATUS_OK) {
                for (i = 0; i < MAX_PLAYERS; i++)
                    if (players[i].used && players[i].admitted && players[i].slot == slot) {
                        printf("host: kicked slot %u (%s)\n", slot, fpp_reason_str(reason));
                        refuse(&players[i], reason, 1);
                    }
            }
        }

        /* ticks; a Checkpoint per epoch */
        while (now_s() >= next_tick) {
            next_tick += TICK_MS / 1000.0;
            tick++;
            fpp_p2p_host_tick(host, (uint64_t)(now_s() * 1000));
            if (tick % TICKS_PER_EPOCH == 0) {
                FppCheckpointBuilder *b = NULL;
                uint8_t cp[MAX_TOKEN], msg[MAX_TOKEN + 64];
                size_t cp_len, msg_len;
                uint8_t build_id[32];
                int signed_ok;

                memset(build_id, 0, sizeof build_id);
                if (fpp_checkpoint_begin(match_id, build_id, 0, epoch, epoch * TICKS_PER_EPOCH,
                                         epoch * TICKS_PER_EPOCH + TICKS_PER_EPOCH - 1, prev, &b) != FPP_STATUS_OK)
                    return 4;
                for (i = 0; i < MAX_PLAYERS; i++)
                    if (players[i].used && players[i].admitted) {
                        uint8_t leaf[2];
                        leaf[0] = (uint8_t)players[i].slot;
                        leaf[1] = (uint8_t)(players[i].slot >> 8);
                        fpp_checkpoint_add_roster(b, leaf, sizeof leaf);
                    }
                signed_ok = fpp_checkpoint_sign(b, instance, cp, sizeof cp, &cp_len) == FPP_STATUS_OK;
                fpp_checkpoint_free(b);
                if (!signed_ok) return 4;
                fpp_object_digest(cp, cp_len, prev);
                if (link) fpp_gs_link_submit_checkpoint(link, cp, cp_len);
                if (fpp_control_checkpoint_head(cp, cp_len, msg, sizeof msg, &msg_len) == FPP_STATUS_OK)
                    for (i = 0; i < MAX_PLAYERS; i++)
                        if (players[i].used && players[i].admitted) send_message(players[i].peer, msg, msg_len);
                epoch++;
            }
            if (fpp_admission_tick(admission, unix_s()) == FPP_STATUS_TOKEN_REVOKED) {
                printf("host: this server is revoked\n");
                seconds = 0;
            }
        }
        flush();
        fflush(stdout);
    }
    for (i = 0; i < MAX_PLAYERS; i++)
        if (players[i].used && players[i].admitted)
            printf("host: slot %u sent %d InputCommits\n", players[i].slot, players[i].commits);
    printf("host: done after %u epochs\n", epoch);
    fpp_p2p_host_free(host);
    fpp_admission_free(admission);
    fpp_gs_link_free(link);
    fpp_signer_free(instance);
    fpp_keys_free(keys);
    close(sock);
    return 0;
}
