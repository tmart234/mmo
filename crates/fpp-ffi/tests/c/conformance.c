/* C conformance test for the FPP SDK, using nothing but fpp.h.
 *
 * It rebuilds three golden objects from interop/vectors/fpp1.json through the
 * C API (same keys and inputs), checks the C verification entry points and
 * error paths, and prints the signed objects as JSON lines so
 * interop/python/check_c_sdk.py can compare them byte-for-byte with the
 * golden vectors and verify them independently. Exit status is the number of
 * failed checks. Built for x86_64 and for i686 (the Halo: CE port's ABI).
 */
#include <stdio.h>
#include <string.h>

#include "fpp.h"

static int failures = 0;

/* An external signer whose hardware always fails (fpp_signer_external). */
static int refusing_signer(void *ctx, const uint8_t *msg, size_t len, uint8_t *sig) {
    (void)ctx;
    (void)msg;
    (void)len;
    (void)sig;
    return -1;
}

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

enum { TICKS_PER_EPOCH = 64, MAX_OBJECT = 1024 };

static const uint8_t MATCH_ID[16] = {'f', 'p', 'p', '1', '-', 'g', 'o', 'l',
                                     'd', 'e', 'n', '-', 'm', 't', 'c', 'h'};

static void print_object(const char *name, const uint8_t *obj, size_t len) {
    size_t i;
    printf("{\"name\": \"%s\", \"cose\": \"", name);
    for (i = 0; i < len; i++) printf("%02x", obj[i]);
    printf("\"}\n");
}

static FppSigner *signer_from_byte(uint8_t b) {
    uint8_t seed[32];
    FppSigner *s = NULL;
    memset(seed, b, sizeof seed);
    CHECK_STATUS(fpp_signer_from_seed(seed, &s), FPP_STATUS_OK);
    return s;
}

/* Frames exactly as the golden vectors define them: payload
 * [tick & 0xff, 0xA5, epoch & 0xff] for every tick of the epoch. */
static FppInputCommitBuilder *commit_builder(uint16_t slot, uint32_t epoch, const uint8_t *prev) {
    FppInputCommitBuilder *b = NULL;
    uint32_t first = epoch * TICKS_PER_EPOCH, t;
    CHECK_STATUS(fpp_input_commit_begin(MATCH_ID, slot, epoch, first, first + TICKS_PER_EPOCH - 1,
                                        prev, &b),
                 FPP_STATUS_OK);
    for (t = first; t < first + TICKS_PER_EPOCH; t++) {
        uint8_t payload[3];
        payload[0] = (uint8_t)(t & 0xff);
        payload[1] = 0xA5;
        payload[2] = (uint8_t)(epoch & 0xff);
        CHECK_STATUS(fpp_input_commit_add_frame(b, t, payload, sizeof payload), FPP_STATUS_OK);
    }
    return b;
}

static size_t sign_commit(FppInputCommitBuilder *b, FppSigner *key, uint8_t *out) {
    size_t need = 0, len = 0;
    /* Size query first, then the real call. */
    CHECK_STATUS(fpp_input_commit_sign(b, key, NULL, 0, &need), FPP_STATUS_BUFFER_TOO_SMALL);
    CHECK(need > 0 && need <= MAX_OBJECT);
    CHECK_STATUS(fpp_input_commit_sign(b, key, out, need - 1, &len), FPP_STATUS_BUFFER_TOO_SMALL);
    CHECK_STATUS(fpp_input_commit_sign(b, key, out, MAX_OBJECT, &len), FPP_STATUS_OK);
    CHECK(len == need);
    return len;
}

static void sha256_str(const char *s, uint8_t out[32]) {
    CHECK_STATUS(fpp_sha256((const uint8_t *)s, strlen(s), out), FPP_STATUS_OK);
}

int main(void) {
    FppSigner *session0 = signer_from_byte(0x51);
    FppSigner *gs = signer_from_byte(0x61);
    uint8_t session_pub[32], gs_pub[32], gs_id[32];
    uint8_t c00[MAX_OBJECT], c01[MAX_OBJECT], cp0[MAX_OBJECT];
    size_t c00_len, c01_len, cp0_len = 0;
    uint8_t c00_digest[32];
    FppInputCommitInfo cinfo;
    FppCheckpointInfo pinfo;
    int i;

    CHECK(fpp_abi_version() == 1);
    for (i = -1; i < 100; i++) CHECK(fpp_status_str(i) != NULL);
    CHECK_STATUS(fpp_signer_public_key(session0, session_pub), FPP_STATUS_OK);
    CHECK_STATUS(fpp_signer_public_key(gs, gs_pub), FPP_STATUS_OK);
    CHECK_STATUS(fpp_key_digest(gs_pub, gs_id), FPP_STATUS_OK);

    /* --- InputCommits: slot 0, epochs 0 and 1, chained by prev. */
    {
        FppInputCommitBuilder *b = commit_builder(0, 0, NULL);
        c00_len = sign_commit(b, session0, c00);
        fpp_input_commit_free(b);
    }
    CHECK_STATUS(fpp_object_digest(c00, c00_len, c00_digest), FPP_STATUS_OK);
    {
        FppInputCommitBuilder *b = commit_builder(0, 1, c00_digest);
        c01_len = sign_commit(b, session0, c01);
        fpp_input_commit_free(b);
    }
    print_object("input-commit/slot0-epoch0", c00, c00_len);
    print_object("input-commit/slot0-epoch1", c01, c01_len);

    CHECK_STATUS(fpp_verify_input_commit(c01, c01_len, session_pub, &cinfo), FPP_STATUS_OK);
    CHECK(cinfo.slot == 0 && cinfo.epoch == 1 && cinfo.n == TICKS_PER_EPOCH);
    CHECK(cinfo.first_tick == 64 && cinfo.last_tick == 127);
    CHECK(memcmp(cinfo.prev, c00_digest, 32) == 0);
    CHECK(memcmp(cinfo.match_id, MATCH_ID, 16) == 0);
    CHECK_STATUS(fpp_verify_input_commit(c01, c01_len, session_pub, NULL), FPP_STATUS_OK);
    /* Wrong key: the object's kid is not the one we were given. */
    CHECK_STATUS(fpp_verify_input_commit(c01, c01_len, gs_pub, NULL), FPP_STATUS_UNKNOWN_KEY);
    /* An InputCommit is never a Checkpoint. */
    CHECK_STATUS(fpp_verify_checkpoint(c01, c01_len, session_pub, NULL), FPP_STATUS_CONTEXT);
    {
        uint8_t bad[MAX_OBJECT];
        memcpy(bad, c01, c01_len);
        bad[c01_len - 1] ^= 0x01; /* inside the signature */
        CHECK_STATUS(fpp_verify_input_commit(bad, c01_len, session_pub, NULL), FPP_STATUS_SIGNATURE);
        CHECK_STATUS(fpp_verify_input_commit(bad, c01_len - 1, session_pub, NULL), FPP_STATUS_ENCODING);
    }

    /* --- Host side: compare received frames with the signed frames_root. */
    {
        FppInputCommitBuilder *received = commit_builder(0, 1, NULL);
        FppInputCommitBuilder *lossy = NULL;
        uint8_t root_all[32], root_lossy[32];
        CHECK_STATUS(fpp_input_commit_frames_root(received, root_all), FPP_STATUS_OK);
        CHECK(memcmp(root_all, cinfo.frames_root, 32) == 0);
        CHECK_STATUS(fpp_input_commit_begin(MATCH_ID, 0, 1, 64, 127, NULL, &lossy), FPP_STATUS_OK);
        CHECK_STATUS(fpp_input_commit_add_frame(lossy, 64, (const uint8_t *)"\x40\xA5\x01", 3),
                     FPP_STATUS_OK);
        CHECK_STATUS(fpp_input_commit_frames_root(lossy, root_lossy), FPP_STATUS_OK);
        CHECK(memcmp(root_lossy, cinfo.frames_root, 32) != 0);
        fpp_input_commit_free(received);
        fpp_input_commit_free(lossy);
    }

    /* --- Checkpoint for epoch 0, as in the golden vectors. */
    {
        FppCheckpointBuilder *b = NULL;
        uint8_t build_id[32], state_root[32], all_applied[8], none_applied[8];
        const char *roster[3] = {"slot0|sat-cti-00|did-aaaa", "slot1|sat-cti-01|did-bbbb",
                                 "slot2|sat-cti-02|did-cccc"};
        sha256_str("gs-build-1.0.0", build_id);
        sha256_str("state@epoch0", state_root);
        memset(all_applied, 0xff, sizeof all_applied);
        memset(none_applied, 0x00, sizeof none_applied);

        CHECK_STATUS(fpp_checkpoint_begin(MATCH_ID, build_id, 42, 0, 0, 63, NULL, &b), FPP_STATUS_OK);
        CHECK_STATUS(fpp_checkpoint_add_input(b, 0, c00_digest, all_applied, 8), FPP_STATUS_OK);
        CHECK_STATUS(fpp_checkpoint_add_input(b, 1, NULL, none_applied, 8), FPP_STATUS_OK);
        /* Slots must ascend; the bitset must cover exactly the epoch's ticks. */
        CHECK_STATUS(fpp_checkpoint_add_input(b, 1, NULL, none_applied, 8), FPP_STATUS_INVALID_ARGUMENT);
        CHECK_STATUS(fpp_checkpoint_add_input(b, 2, NULL, none_applied, 7), FPP_STATUS_INVALID_ARGUMENT);
        CHECK_STATUS(fpp_checkpoint_add_input(b, 2, NULL, none_applied, 8), FPP_STATUS_OK);
        CHECK_STATUS(fpp_checkpoint_add_event(b, (const uint8_t *)"spawn|slot0", 11), FPP_STATUS_OK);
        for (i = 0; i < 3; i++) {
            CHECK_STATUS(fpp_checkpoint_add_roster(b, (const uint8_t *)roster[i], strlen(roster[i])),
                         FPP_STATUS_OK);
        }
        CHECK_STATUS(fpp_checkpoint_set_state_root(b, state_root), FPP_STATUS_OK);
        CHECK_STATUS(fpp_checkpoint_sign(b, gs, cp0, sizeof cp0, &cp0_len), FPP_STATUS_OK);
        fpp_checkpoint_free(b);
    }
    print_object("checkpoint/epoch0", cp0, cp0_len);

    CHECK_STATUS(fpp_verify_checkpoint(cp0, cp0_len, gs_pub, &pinfo), FPP_STATUS_OK);
    CHECK(memcmp(pinfo.gs_instance_id, gs_id, 32) == 0);
    CHECK(pinfo.policy_ver == 42 && pinfo.epoch == 0 && pinfo.first_tick == 0 && pinfo.last_tick == 63);
    CHECK(pinfo.inputs_n == 3 && pinfo.events_n == 1 && pinfo.rng_n == 0 && pinfo.roster_n == 3);
    /* A session key must never be accepted for a Checkpoint. */
    CHECK_STATUS(fpp_verify_checkpoint(cp0, cp0_len, session_pub, NULL), FPP_STATUS_UNKNOWN_KEY);

    /* --- Argument validation. */
    {
        FppInputCommitBuilder *b = NULL;
        size_t len = 0;
        CHECK_STATUS(fpp_input_commit_begin(NULL, 0, 0, 0, 1, NULL, &b), FPP_STATUS_NULL_POINTER);
        CHECK_STATUS(fpp_input_commit_begin(MATCH_ID, 0, 0, 5, 4, NULL, &b), FPP_STATUS_INVALID_ARGUMENT);
        CHECK_STATUS(fpp_input_commit_begin(MATCH_ID, 0, 0, 0, 63, NULL, NULL), FPP_STATUS_NULL_POINTER);
        CHECK_STATUS(fpp_input_commit_begin(MATCH_ID, 0, 0, 0, 63, NULL, &b), FPP_STATUS_OK);
        CHECK_STATUS(fpp_input_commit_add_frame(b, 10, NULL, 0), FPP_STATUS_OK);
        CHECK_STATUS(fpp_input_commit_add_frame(b, 10, NULL, 0), FPP_STATUS_INVALID_ARGUMENT);
        CHECK_STATUS(fpp_input_commit_add_frame(b, 9, NULL, 0), FPP_STATUS_INVALID_ARGUMENT);
        CHECK_STATUS(fpp_input_commit_add_frame(b, 64, NULL, 0), FPP_STATUS_INVALID_ARGUMENT);
        CHECK_STATUS(fpp_input_commit_add_frame(b, 11, NULL, 3), FPP_STATUS_NULL_POINTER);
        CHECK_STATUS(fpp_input_commit_add_frame(NULL, 11, NULL, 0), FPP_STATUS_NULL_POINTER);
        CHECK_STATUS(fpp_input_commit_sign(b, NULL, NULL, 0, &len), FPP_STATUS_NULL_POINTER);
        CHECK_STATUS(fpp_input_commit_sign(b, session0, NULL, 0, NULL), FPP_STATUS_NULL_POINTER);
        CHECK_STATUS(fpp_verify_input_commit(NULL, 10, session_pub, NULL), FPP_STATUS_NULL_POINTER);
        fpp_input_commit_free(b);
        fpp_input_commit_free(NULL);
        fpp_checkpoint_free(NULL);
        fpp_signer_free(NULL);
    }

    /* Fresh random keys work end to end. */
    {
        FppSigner *fresh = NULL;
        uint8_t pub[32], obj[MAX_OBJECT];
        size_t len = 0;
        FppInputCommitBuilder *b = commit_builder(7, 3, NULL);
        CHECK_STATUS(fpp_signer_generate(&fresh), FPP_STATUS_OK);
        CHECK_STATUS(fpp_signer_public_key(fresh, pub), FPP_STATUS_OK);
        CHECK_STATUS(fpp_input_commit_sign(b, fresh, obj, sizeof obj, &len), FPP_STATUS_OK);
        CHECK_STATUS(fpp_verify_input_commit(obj, len, pub, NULL), FPP_STATUS_OK);
        fpp_input_commit_free(b);
        fpp_signer_free(fresh);
    }

    /* Platform evidence (P3): the challenge, checked against an independent
       SHA-256 of "fpp/1/attest-challenge" || 0x00 || 01*32 || 02*32 (Python
       hashlib), and the envelopes' size protocol. */
    {
        static const uint8_t want[32] = {
            0x22, 0x23, 0xb7, 0x60, 0x37, 0x27, 0xd8, 0xc6, 0xc6, 0xcf, 0x3c, 0x4f, 0xe9, 0x44, 0x33, 0xed,
            0xa2, 0x1f, 0xa3, 0x0d, 0xef, 0xce, 0x05, 0xd4, 0x43, 0x27, 0x7f, 0xdc, 0xa7, 0x43, 0xf9, 0x31};
        uint8_t ones[32], twos[32], got[32], env[256];
        const uint8_t leaf[3] = {0x30, 0x01, 0x00}, inter[2] = {0x30, 0x00};
        const uint8_t *certs[2] = {leaf, inter};
        const size_t lens[2] = {sizeof leaf, sizeof inter};
        size_t need = 0, len = 0;
        memset(ones, 1, 32);
        memset(twos, 2, 32);
        CHECK_STATUS(fpp_attest_challenge(ones, twos, got), FPP_STATUS_OK);
        CHECK(memcmp(got, want, 32) == 0);
        CHECK_STATUS(fpp_attest_challenge(NULL, twos, got), FPP_STATUS_NULL_POINTER);
        /* the same through the variable-length entry point (a valid key of
           32 bytes: Ed25519), and for a key that will itself be the session
           key: SHA-256("fpp/1/attest-challenge" || 0x00 || 01*32) */
        {
            uint8_t fixed_len[32];
            CHECK_STATUS(fpp_attest_challenge(ones, session_pub, fixed_len), FPP_STATUS_OK);
            CHECK_STATUS(fpp_attest_challenge_key(ones, session_pub, 32, got), FPP_STATUS_OK);
            CHECK(memcmp(got, fixed_len, 32) == 0);
            CHECK_STATUS(fpp_attest_challenge_key(ones, session_pub, 31, got), FPP_STATUS_INVALID_ARGUMENT);
        }
        {
            static const uint8_t want_hw[32] = {
                0xec, 0xba, 0x6d, 0x90, 0xf0, 0x7b, 0x53, 0x3e, 0x93, 0x5c, 0x65, 0x36, 0x59, 0x71, 0x44, 0x3c,
                0x69, 0xd9, 0xc3, 0xd0, 0x5b, 0x2b, 0x19, 0xb3, 0x55, 0x6c, 0x8e, 0x40, 0xee, 0x38, 0x76, 0x79};
            CHECK_STATUS(fpp_attest_challenge_hw_key(ones, got), FPP_STATUS_OK);
            CHECK(memcmp(got, want_hw, 32) == 0);
        }
        CHECK_STATUS(fpp_evidence_android_key(certs, lens, 2, NULL, 0, &need), FPP_STATUS_BUFFER_TOO_SMALL);
        CHECK(need > 0 && need <= sizeof env);
        CHECK_STATUS(fpp_evidence_android_key(certs, lens, 2, env, sizeof env, &len), FPP_STATUS_OK);
        CHECK(len == need);
        CHECK_STATUS(fpp_evidence_android_key(certs, lens, 0, env, sizeof env, &len), FPP_STATUS_INVALID_ARGUMENT);
        CHECK_STATUS(fpp_evidence_apple_attest(leaf, sizeof leaf, env, sizeof env, &len), FPP_STATUS_OK);
        CHECK_STATUS(fpp_evidence_apple_assert(twos, leaf, sizeof leaf, env, sizeof env, &len), FPP_STATUS_OK);
        CHECK_STATUS(fpp_evidence_apple_assert(twos, leaf, 0, env, sizeof env, &len), FPP_STATUS_INVALID_ARGUMENT);
    }

    /* External signers (P3): a callback that fails yields SIGNER_FAILED and
       no object, not an invalid one. */
    {
        FppSigner *ext = NULL;
        FppInputCommitBuilder *b = commit_builder(0, 0, NULL);
        uint8_t out[MAX_OBJECT];
        size_t len = 0;
        CHECK_STATUS(fpp_signer_external(session_pub, refusing_signer, NULL, &ext), FPP_STATUS_OK);
        CHECK_STATUS(fpp_input_commit_sign(b, ext, out, sizeof out, &len), FPP_STATUS_SIGNER_FAILED);
        CHECK_STATUS(fpp_signer_external(session_pub, NULL, NULL, &ext), FPP_STATUS_NULL_POINTER);
        fpp_input_commit_free(b);
        fpp_signer_free(ext);
    }

    fpp_signer_free(session0);
    fpp_signer_free(gs);
    fprintf(stderr, "C conformance (%u-bit): %d failure(s)\n", (unsigned)(sizeof(void *) * 8), failures);
    return failures;
}
