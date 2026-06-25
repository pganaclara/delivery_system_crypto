// =============================================================================
// Distributed Homomorphic DES — Cargo-Transfer Delivery System (3 × ESP32-S3)
// =============================================================================
//
// Running example: three autonomous UAVs and one shared transfer buffer B.
//
//        a1        b1          a2        b2
//   warehouse ──► D1 ──► [ buffer B ] ──► D2 ──► client
//                              │  a3       b3
//                              └────────► D3 ──► client
//
//   D1 carries packages warehouse → B           (this node emits b1, +1 to B)
//   D2, D3 collect from B and deliver to client (these nodes emit a2/a3, −1)
//   B is a shared store with LIMITED CAPACITY (cap = 2 in the generated .h).
//
// ── ONE ESP32-S3 PER UAV ─────────────────────────────────────────────────────
// This sketch is flashed to all THREE boards. Set NODE_ID (1, 2 or 3) per board
// at the top of the configuration block (or with a -DNODE_ID=n build flag).
//
//   NODE_ID 1 → D1   (controllable a1, deposits b1)
//   NODE_ID 2 → D2   (controllable a2 = pickup)
//   NODE_ID 3 → D3   (controllable a3 = pickup)
//
// ── WHAT IS PRIVATE ──────────────────────────────────────────────────────────
// Each board holds the shared buffer supervisor as EC-ElGamal CIPHERTEXTS in
// RAM (the reduced 3-state buffer-level supervisor from the .h). The buffer
// LEVEL is never stored or transmitted in the clear. Each step decrypts only
// one enablement BIT — "may my UAV act right now?" — exactly as in the original
// single-board homomorphic-esp32-ultrades.ino. This is the same HE core; the
// new part is the distribution layer.
//
// ── HOW THE THREE BOARDS COORDINATE ──────────────────────────────────────────
// Model chosen: REPLICATED BUFFER + BROADCAST (leaderless).
//   • Every board runs an identical encrypted replica of the buffer supervisor.
//   • The only events that change the buffer are b1 (+1), a2 (−1), a3 (−1).
//     Whenever one board fires such an event it sends it to all peers over the
//     WiFi TCP mesh; every board applies the same homomorphic transition, so all
//     replicas stay in lock-step.
//   • A 1-token ring (node1→node2→node3→node1) serialises buffer mutations so
//     the two consumers D2/D3 can never both decrement an empty buffer. The
//     supervisor is *permissive* (it allows a2 AND a3 when B≥1); the token is
//     the physical mutual-exclusion the supervisor deliberately does not impose.
//     This is the co-observability gap discussed in decentralised SCT
//     (Rudie & Wonham 1992) — see README notes.
//
// A board, when it holds the token:
//   1. applies any buffer events it has received,
//   2. asks the homomorphic supervisor whether ITS controllable event is
//      enabled in the current (encrypted) buffer state,
//   3. if enabled and its UAV is idle, runs one UAV cycle and broadcasts the
//      buffer-changing event,
//   4. passes the token to the next board.
//
// ── REQUIREMENTS ─────────────────────────────────────────────────────────────
//   • ESP32 Arduino core v3.x, board = "ESP32S3 Dev Module"
//   • Drop  supervisor_data_delivery_system.h  AND  sdkconfig.ext  in this
//     folder (already copied here).
//   • No external libraries — WiFi/TCP is in the core; crypto uses the core's
//     bundled mbedTLS.
//   • Set WIFI_SSID / WIFI_PASS (and the subnet octets) in the config block.
//   • Flash all 3 boards, each with a different NODE_ID. Serial @ 115200.
// =============================================================================

#include <Arduino.h>
#include <WiFi.h>            // also provides WiFiServer / WiFiClient (TCP)
#include <esp_timer.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <pgmspace.h>
#include <vector>

#include "supervisor_data_delivery_system.h"

// =============================================================================
// Per-board configuration
// =============================================================================

// >>> SET THIS PER BOARD <<<  (1 = D1, 2 = D2, 3 = D3). Or build with -DNODE_ID=2
#ifndef NODE_ID
#define NODE_ID 2
#endif

#define NUM_NODES 3

// >>> SOLO TEST MODE <<<  Set to 1 to bench-test with a SINGLE board: this board
// plays all three UAV roles (D1→D2→D3) in turn on one shared encrypted buffer
// replica, with NO networking and no other boards needed. The onboard LED cycles
// through the role colours as each UAV acts. Set back to 0 for the real
// distributed 3-board system. (Or build with -DSOLO_TEST=1.)
#ifndef SOLO_TEST
#define SOLO_TEST 0
#endif

// Simulated flight time (ms) for a UAV trip leg. Keeps the demo watchable.
#define FLIGHT_MS        1500
// How long a board keeps the token when it has nothing to do, before passing.
#define IDLE_HOLD_MS     400
// Probability (%) that an idle, enabled UAV is actually ready to act this turn.
// Models real autonomy (battery / next package not always ready) and keeps the
// two consumers D2/D3 from starving each other under a fixed token order.
#define READY_PCT        65
// ── WiFi + TCP transport ─────────────────────────────────────────────────────
// All three boards join the same WiFi access point and talk over a small TCP
// mesh (each pair of boards keeps one connection). >>> SET YOUR AP CREDENTIALS <<<
#define WIFI_SSID   "yourSSID"
#define WIFI_PASS   "yourPassword"
#define TCP_PORT    3333
// Static IPs so the boards can find each other without any discovery. Set the
// first three octets to match YOUR router's subnet (e.g. 192.168.0 or 192.168.1).
// Each board gets  <subnet>.(NET_IP_BASE + NODE_ID), gateway <subnet>.1.
#define NET_O1 192
#define NET_O2 168
#define NET_O3 1
#define NET_IP_BASE 50            // node1=.51, node2=.52, node3=.53

// ── Global event indices (must match EVENT_NAMES[] in the .h) ────────────────
// .h order is sorted: a1=0, a2=1, a3=2, b1=3, b2=4, b3=5
#define EV_A1 0
#define EV_A2 1
#define EV_A3 2
#define EV_B1 3
#define EV_B2 4
#define EV_B3 5

// ── Role table: what each node controls / emits ──────────────────────────────
// gate_gi   : controllable event whose enablement we check before acting
// buf_gi    : the buffer-changing event this node fires (broadcast to all)
// emit_after_flight : producer (D1) deposits at END of trip; consumers (D2/D3)
//                     pick up at the START of their trip.
struct Role { const char* uav; int gate_gi; int buf_gi; bool emit_after_flight; };
static const Role ROLES[NUM_NODES + 1] = {
    /* [0] unused */ { "",  -1, -1, false },
    /* node 1 D1  */ { "D1", EV_A1, EV_B1, true  },  // take off (a1) → fly → deposit (b1,+1)
    /* node 2 D2  */ { "D2", EV_A2, EV_A2, false },  // pick up (a2,−1) → fly → deliver (b2)
    /* node 3 D3  */ { "D3", EV_A3, EV_A3, false },  // pick up (a3,−1) → fly → deliver (b3)
};
static const Role& ROLE = ROLES[NODE_ID];

// =============================================================================
// Crypto / HE configuration (identical to the original sketch)
// =============================================================================

#define CURVE      MBEDTLS_ECP_DP_SECP192R1
#define CURVE_NAME "secp192r1"
#define PT_LEN     25                              // 1 prefix + 24-byte X coord

// Scalar blinding on decrypt is always on (per-board DRBG). Cell
// re-randomisation (the expensive memory-side-channel hardening) is OFF by
// default so the node stays responsive; flip to 1 for the research build.
#ifndef SECURITY_FULL_RERANDOMIZE
#define SECURITY_FULL_RERANDOMIZE 0
#endif

// =============================================================================
// Types
// =============================================================================

struct Ciphertext { uint8_t c1[PT_LEN]; uint8_t c2[PT_LEN]; };

struct Supervisor {
    const SupDesc* desc;
    uint32_t       own_event_mask   = 0;
    uint32_t       trans_event_mask = 0;
    std::vector<uint8_t>           constrained_gi;
    std::vector<Ciphertext>        enc;
    std::vector<mbedtls_ecp_point> dec_c1, dec_c2;
    std::vector<int8_t>            cached_en;
    std::vector<std::vector<uint8_t>> changes_if_zero;
    std::vector<std::vector<uint8_t>> changes_if_one;
};

// Wire message — a fixed 8-byte frame sent over the TCP mesh.
enum MsgType : uint8_t { MSG_EVENT = 1, MSG_TOKEN = 2 };
struct __attribute__((packed)) Msg {
    uint8_t  type;    // MsgType
    uint8_t  src;     // sender node id
    uint8_t  dst;     // MSG_TOKEN: target node id; MSG_EVENT: 0 (everyone)
    uint8_t  ev;      // MSG_EVENT: global event index
    uint32_t gseq;    // global event sequence number (monotone, serialised)
};

// =============================================================================
// Globals — crypto
// =============================================================================

static std::vector<Supervisor>  g_sups;
static mbedtls_ecp_group        g_grp;
static mbedtls_ecp_point        g_G, g_pub;
static mbedtls_mpi              g_priv, g_one, g_neg_priv;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_entropy_context  g_entropy;
static Ciphertext               g_zero;            // canonical Enc(0) literal

// =============================================================================
// Globals — distributed state
// =============================================================================

static volatile bool     g_have_token    = false;
static volatile uint32_t g_token_gseq    = 0;       // gseq carried by last token
static uint32_t          g_applied_gseq  = 0;       // events applied to our replica
static bool              g_uav_idle      = true;    // our UAV physical status

// Small inbound ring buffer for events received from peers (filled by net_poll
// in loop context, drained by drain_events()).
struct EvIn { uint8_t ev; uint32_t gseq; };
static volatile int  g_evq_head = 0, g_evq_tail = 0;
static EvIn          g_evq[16];
static portMUX_TYPE  g_q_mux = portMUX_INITIALIZER_UNLOCKED;

// =============================================================================
// PROGMEM helpers
// =============================================================================

inline int8_t   pm_i8 (const int8_t*   a, int i) { return (int8_t) pgm_read_byte(a+i); }
inline int16_t  pm_i16(const int16_t*  a, int i) { return (int16_t)pgm_read_word(a+i); }
inline uint16_t pm_u16(const uint16_t* a, int i) { return (uint16_t)pgm_read_word(a+i); }

static inline bool is_g_zero(const Ciphertext& c) {
    return memcmp(&c, &g_zero, sizeof(Ciphertext)) == 0;
}
static int trans_offset(const SupDesc* desc, int ev) {
    int off = 0; for (int i = 0; i < ev; ++i) off += (int)pm_u16(desc->tcnt, i); return off;
}
static inline void swap_pt(mbedtls_ecp_point* a, mbedtls_ecp_point* b) {
    mbedtls_ecp_point t = *a; *a = *b; *b = t;
}
static void sv_free_dec(Supervisor& sv) {
    for (auto& p : sv.dec_c1) mbedtls_ecp_point_free(&p);
    for (auto& p : sv.dec_c2) mbedtls_ecp_point_free(&p);
    sv.dec_c1.clear(); sv.dec_c2.clear();
}

// =============================================================================
// EC point I/O + EC-ElGamal primitives (verbatim from the original sketch)
// =============================================================================

static int pt_compress(const mbedtls_ecp_point* P, uint8_t out[PT_LEN]) {
    size_t len = 0;
    return mbedtls_ecp_point_write_binary(&g_grp, P, MBEDTLS_ECP_PF_COMPRESSED, &len, out, PT_LEN);
}
static int pt_decompress(const uint8_t in[PT_LEN], mbedtls_ecp_point* P) {
    mbedtls_ecp_point_init(P);
    return mbedtls_ecp_point_read_binary(&g_grp, P, in, PT_LEN);
}
static int pt_add(mbedtls_ecp_point* R, const mbedtls_ecp_point* P, const mbedtls_ecp_point* Q) {
    return mbedtls_ecp_muladd(&g_grp, R, &g_one, P, &g_one, Q);
}

static int elgamal_enc(int m, Ciphertext* ct, mbedtls_ctr_drbg_context* drbg) {
    mbedtls_mpi r; mbedtls_mpi_init(&r);
    mbedtls_ecp_point rP, c1, c2;
    mbedtls_ecp_point_init(&rP); mbedtls_ecp_point_init(&c1); mbedtls_ecp_point_init(&c2);
    int ret = mbedtls_ecp_gen_privkey(&g_grp, &r, mbedtls_ctr_drbg_random, drbg); if (ret) goto done;
    ret = mbedtls_ecp_mul(&g_grp, &c1, &r, &g_G,   mbedtls_ctr_drbg_random, drbg); if (ret) goto done;
    ret = mbedtls_ecp_mul(&g_grp, &rP, &r, &g_pub, mbedtls_ctr_drbg_random, drbg); if (ret) goto done;
    if (m == 0) {
        mbedtls_ecp_copy(&c2, &rP);
    } else {
        mbedtls_ecp_point mG; mbedtls_mpi mm;
        mbedtls_ecp_point_init(&mG); mbedtls_mpi_init(&mm);
        mbedtls_mpi_lset(&mm, m);
        ret = mbedtls_ecp_mul(&g_grp, &mG, &mm, &g_G, mbedtls_ctr_drbg_random, drbg);
        if (ret == 0) ret = pt_add(&c2, &mG, &rP);
        mbedtls_ecp_point_free(&mG); mbedtls_mpi_free(&mm);
    }
    if (ret) goto done;
    ret = pt_compress(&c1, ct->c1);
    if (ret == 0) ret = pt_compress(&c2, ct->c2);
done:
    mbedtls_ecp_point_free(&rP); mbedtls_ecp_point_free(&c1); mbedtls_ecp_point_free(&c2);
    mbedtls_mpi_free(&r);
    return ret;
}

static int elgamal_dec(const Ciphertext* ct, int* out) {
    mbedtls_ecp_point c1, c2, pm;
    mbedtls_ecp_point_init(&c1); mbedtls_ecp_point_init(&c2); mbedtls_ecp_point_init(&pm);
    int ret = pt_decompress(ct->c1, &c1); if (ret) goto done;
    ret     = pt_decompress(ct->c2, &c2); if (ret) goto done;
    ret = mbedtls_ecp_muladd(&g_grp, &pm, &g_neg_priv, &c1, &g_one, &c2);
    if (ret == 0) *out = mbedtls_ecp_is_zero(&pm) ? 0 : 1;
done:
    mbedtls_ecp_point_free(&c1); mbedtls_ecp_point_free(&c2); mbedtls_ecp_point_free(&pm);
    return ret;
}

// =============================================================================
// Hot path: fused row-sum + blinded decrypt (single-core variant)
// =============================================================================

static int row_decrypt(const Supervisor& sv, const int8_t* row, int n,
                       int* out, bool* did_decrypt) {
    *did_decrypt = false;
    int first = -1;
    for (int i = 0; i < n; ++i) {
        if (!pm_i8(row, i))       continue;
        if (is_g_zero(sv.enc[i])) continue;
        first = i; break;
    }
    if (first < 0) { *out = 0; return 0; }

    mbedtls_ecp_point s1, s2, tmp;
    mbedtls_ecp_point_init(&s1); mbedtls_ecp_point_init(&s2); mbedtls_ecp_point_init(&tmp);
    int ret = mbedtls_ecp_copy(&s1, &sv.dec_c1[first]); if (ret) goto done;
    ret     = mbedtls_ecp_copy(&s2, &sv.dec_c2[first]); if (ret) goto done;

    for (int i = first + 1; i < n; ++i) {
        if (!pm_i8(row, i))       continue;
        if (is_g_zero(sv.enc[i])) continue;
        ret = mbedtls_ecp_muladd(&g_grp, &tmp, &g_one, &s1, &g_one, &sv.dec_c1[i]); if (ret) goto done;
        swap_pt(&s1, &tmp);
        ret = mbedtls_ecp_muladd(&g_grp, &tmp, &g_one, &s2, &g_one, &sv.dec_c2[i]); if (ret) goto done;
        swap_pt(&s2, &tmp);
    }
    {
        mbedtls_ecp_point ns, pm;
        mbedtls_ecp_point_init(&ns); mbedtls_ecp_point_init(&pm);
        ret = mbedtls_ecp_mul(&g_grp, &ns, &g_neg_priv, &s1, mbedtls_ctr_drbg_random, &g_drbg);
        if (ret == 0) ret = mbedtls_ecp_muladd(&g_grp, &pm, &g_one, &s2, &g_one, &ns);
        if (ret == 0) { *out = mbedtls_ecp_is_zero(&pm) ? 0 : 1; *did_decrypt = true; }
        mbedtls_ecp_point_free(&ns); mbedtls_ecp_point_free(&pm);
    }
done:
    mbedtls_ecp_point_free(&s1); mbedtls_ecp_point_free(&s2); mbedtls_ecp_point_free(&tmp);
    return ret;
}

// Apply event ev_gi's transitions to sv (ciphertext + decompressed cache).
static void do_transition(Supervisor& sv, int ev_gi, int n) {
    int      off = trans_offset(sv.desc, ev_gi);
    uint16_t pc  = pm_u16(sv.desc->tcnt, ev_gi);
    std::vector<Ciphertext>        nxt(n, g_zero);
    std::vector<mbedtls_ecp_point> nxt_c1(n), nxt_c2(n);
    for (int i = 0; i < n; ++i) { mbedtls_ecp_point_init(&nxt_c1[i]); mbedtls_ecp_point_init(&nxt_c2[i]); }
    for (uint16_t p = 0; p < pc; ++p) {
        int from = pm_i16(sv.desc->trans + off * 2, p * 2);
        int to   = pm_i16(sv.desc->trans + off * 2, p * 2 + 1);
        nxt[to]  = sv.enc[from];
        if (!is_g_zero(sv.enc[from])) {
            mbedtls_ecp_copy(&nxt_c1[to], &sv.dec_c1[from]);
            mbedtls_ecp_copy(&nxt_c2[to], &sv.dec_c2[from]);
        }
    }
    sv_free_dec(sv);
    sv.enc    = std::move(nxt);
    sv.dec_c1 = std::move(nxt_c1);
    sv.dec_c2 = std::move(nxt_c2);
}

// =============================================================================
// Homomorphic step (single supervisor, single core)
// =============================================================================
//
// Applies the fired event to the encrypted replica and refreshes the cached
// enablement bits for any row that could have flipped.
static int he_step(int ev_gi) {
    for (auto& sv : g_sups) {
        if (!(sv.trans_event_mask & (1u << ev_gi))) continue;
        int n = (int)pgm_read_word(&sv.desc->num_states);
        do_transition(sv, ev_gi, n);
        for (uint8_t li : sv.changes_if_zero[ev_gi])
            if (sv.cached_en[li] == 0) {
                int e; bool dd; int gi = sv.constrained_gi[li];
                if (row_decrypt(sv, sv.desc->enable + gi * n, n, &e, &dd) == 0) sv.cached_en[li] = (int8_t)e;
            }
        for (uint8_t li : sv.changes_if_one[ev_gi])
            if (sv.cached_en[li] == 1) {
                int e; bool dd; int gi = sv.constrained_gi[li];
                if (row_decrypt(sv, sv.desc->enable + gi * n, n, &e, &dd) == 0) sv.cached_en[li] = (int8_t)e;
            }
    }
    return 0;
}

// Is global event gi currently enabled by every supervisor? Reads the cached
// (decrypted) enablement bits — no new decryption needed.
static bool event_enabled(int gi) {
    for (auto& sv : g_sups)
        for (size_t li = 0; li < sv.constrained_gi.size(); ++li)
            if (sv.constrained_gi[li] == gi && !sv.cached_en[li]) return false;
    return true;
}

// =============================================================================
// Supervisor loading + invariance precompute (verbatim from original)
// =============================================================================

static bool load_supervisors(const SupDesc* descs, int count) {
    g_sups.clear(); g_sups.resize(count);
    for (int i = 0; i < count; ++i) {
        Supervisor& sv = g_sups[i];
        sv.desc = &descs[i];
        int n = (int)pgm_read_word(&descs[i].num_states);
        for (int gi = 0; gi < EVENT_COUNT; ++gi) {
            if (pm_u16(descs[i].tcnt, gi) > 0) { sv.own_event_mask |= (1u<<gi); sv.trans_event_mask |= (1u<<gi); }
            bool constrains = false;
            for (int s = 0; s < n && !constrains; ++s) if (!pm_i8(descs[i].enable, gi*n+s)) constrains = true;
            if (constrains) { sv.own_event_mask |= (1u<<gi); sv.constrained_gi.push_back((uint8_t)gi); }
        }
        sv.cached_en.assign(sv.constrained_gi.size(), 1);
        sv.changes_if_zero.assign(EVENT_COUNT, {});
        sv.changes_if_one .assign(EVENT_COUNT, {});
        for (int ev = 0; ev < EVENT_COUNT; ++ev) {
            uint16_t pc = pm_u16(descs[i].tcnt, ev);
            if (pc == 0) continue;
            int off = trans_offset(&descs[i], ev);
            std::vector<uint8_t> in_from(n, 0);
            std::vector<int16_t> trans_to(n, -1);
            for (int p = 0; p < pc; ++p) {
                int f = pm_i16(descs[i].trans + off*2, p*2);
                int t = pm_i16(descs[i].trans + off*2, p*2+1);
                in_from[f] = 1; trans_to[f] = (int16_t)t;
            }
            for (int li = 0; li < (int)sv.constrained_gi.size(); ++li) {
                int gi = sv.constrained_gi[li];
                const int8_t* row = descs[i].enable + gi*n;
                bool any_en = false;
                for (int s = 0; s < n && !any_en; ++s) if (pm_i8(row, s)) any_en = true;
                if (!any_en) { sv.cached_en[li] = 0; continue; }
                bool z2o = false;
                for (int p = 0; p < pc && !z2o; ++p) {
                    int f = pm_i16(descs[i].trans + off*2, p*2);
                    int t = pm_i16(descs[i].trans + off*2, p*2+1);
                    if (!pm_i8(row, f) && pm_i8(row, t)) z2o = true;
                }
                if (z2o) sv.changes_if_zero[ev].push_back((uint8_t)li);
                bool o2z = false;
                for (int s = 0; s < n && !o2z; ++s) {
                    if (!pm_i8(row, s)) continue;
                    if (!in_from[s])              { o2z = true; break; }
                    if (!pm_i8(row, trans_to[s])) { o2z = true; break; }
                }
                if (o2z) sv.changes_if_one[ev].push_back((uint8_t)li);
            }
        }
        char name[16]; strncpy_P(name, (const char*)pgm_read_ptr(&descs[i].name), 15); name[15] = 0;
        Serial.printf("[LOAD] %-10s %d states, %d constraining events\n",
                      name, n, (int)sv.constrained_gi.size());
    }
    return true;
}

static bool init_states() {
    for (auto& sv : g_sups) {
        int n = (int)pgm_read_word(&sv.desc->num_states);
        sv.enc.resize(n);
        sv_free_dec(sv); sv.dec_c1.resize(n); sv.dec_c2.resize(n);
        for (int s = 0; s < n; ++s) { mbedtls_ecp_point_init(&sv.dec_c1[s]); mbedtls_ecp_point_init(&sv.dec_c2[s]); }
        for (int s = 0; s < n; ++s) {
            yield();
            if (elgamal_enc((int)pm_i8(sv.desc->init, s), &sv.enc[s], &g_drbg) != 0) return false;
            pt_decompress(sv.enc[s].c1, &sv.dec_c1[s]);
            pt_decompress(sv.enc[s].c2, &sv.dec_c2[s]);
        }
    }
    return true;
}

static void warm_cache() {
    for (auto& sv : g_sups)
        for (size_t li = 0; li < sv.constrained_gi.size(); ++li) {
            int n = (int)pgm_read_word(&sv.desc->num_states);
            int gi = sv.constrained_gi[li];
            int e; bool dd;
            if (row_decrypt(sv, sv.desc->enable + gi*n, n, &e, &dd) == 0) sv.cached_en[li] = (int8_t)e;
        }
}

static void crypto_init() {
    mbedtls_ecp_group_init(&g_grp);
    mbedtls_ecp_point_init(&g_G); mbedtls_ecp_point_init(&g_pub);
    mbedtls_mpi_init(&g_priv); mbedtls_mpi_init(&g_one); mbedtls_mpi_init(&g_neg_priv);
    mbedtls_ctr_drbg_init(&g_drbg); mbedtls_entropy_init(&g_entropy);
    mbedtls_mpi_lset(&g_one, 1);
    const char* pers = "esp32_he_uav";
    mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy, (const uint8_t*)pers, strlen(pers));
    mbedtls_ecp_group_load(&g_grp, CURVE);
    mbedtls_ecp_copy(&g_G, &g_grp.G);
    mbedtls_ecp_gen_keypair(&g_grp, &g_priv, &g_pub, mbedtls_ctr_drbg_random, &g_drbg);
    mbedtls_mpi_sub_mpi(&g_neg_priv, &g_grp.N, &g_priv);
    elgamal_enc(0, &g_zero, &g_drbg);
}

// =============================================================================
// WiFi + TCP transport (mesh)
// =============================================================================
//
// Each pair of boards keeps a single TCP connection (lower NODE_ID connects to
// higher; higher listens). Every Msg is written to all connected peers and
// filtered on receipt — same broadcast-and-filter model as the ESP-NOW version,
// so none of the coordination logic below had to change. Messages are fixed
// 8-byte frames, so the reader just accumulates bytes until it has a whole Msg.

static void enqueue_event(uint8_t ev, uint32_t gseq) {
    portENTER_CRITICAL_ISR(&g_q_mux);
    int nxt = (g_evq_head + 1) % 16;
    if (nxt != g_evq_tail) { g_evq[g_evq_head] = {ev, gseq}; g_evq_head = nxt; }
    portEXIT_CRITICAL_ISR(&g_q_mux);
}
static bool dequeue_event(EvIn* out) {
    bool got = false;
    portENTER_CRITICAL(&g_q_mux);
    if (g_evq_tail != g_evq_head) { *out = g_evq[g_evq_tail]; g_evq_tail = (g_evq_tail+1)%16; got = true; }
    portEXIT_CRITICAL(&g_q_mux);
    return got;
}

// One TCP link to a peer board (at most NUM_NODES-1 of them per board).
struct Link {
    WiFiClient cli;
    uint8_t    buf[sizeof(Msg)];
    uint8_t    have    = 0;       // bytes accumulated toward the next 8-byte frame
    bool       outgoing = false;  // true = we connect out (to a higher NODE_ID)
    uint8_t    peer     = 0;      // target NODE_ID (outgoing links only)
};
static Link    g_links[NUM_NODES - 1];
static int     g_nlinks = 0;
static WiFiServer g_server(TCP_PORT);

static IPAddress node_ip(int id) { return IPAddress(NET_O1, NET_O2, NET_O3, NET_IP_BASE + id); }

// Handle one fully-received 8-byte Msg.
static void handle_msg(const Msg& m) {
    if (m.type == MSG_EVENT) {
        enqueue_event(m.ev, m.gseq);
    } else if (m.type == MSG_TOKEN && m.dst == NODE_ID) {
        g_token_gseq = m.gseq;
        g_have_token = true;
    }
}

// Send a Msg to every connected peer (broadcast-and-filter, like ESP-NOW).
static void send_msg(const Msg& m) {
    for (int i = 0; i < g_nlinks; ++i)
        if (g_links[i].cli.connected())
            g_links[i].cli.write((const uint8_t*)&m, sizeof(m));
}

// Accept incoming connections and (re)connect outgoing ones; read any data.
static void net_poll() {
    // Accept an incoming connection into a free incoming slot.
    WiFiClient inc = g_server.accept();
    if (inc) {
        bool placed = false;
        for (int i = 0; i < g_nlinks; ++i) {
            if (!g_links[i].outgoing && !g_links[i].cli.connected()) {
                g_links[i].cli = inc; g_links[i].have = 0; placed = true; break;
            }
        }
        if (!placed) inc.stop();   // no room (shouldn't happen with 3 nodes)
    }

    // Reconnect any dropped outgoing links (non-blocking-ish; short timeout).
    static uint32_t last_try = 0;
    if (millis() - last_try > 1000) {
        last_try = millis();
        for (int i = 0; i < g_nlinks; ++i) {
            Link& L = g_links[i];
            if (L.outgoing && !L.cli.connected()) {
                if (L.cli.connect(node_ip(L.peer), TCP_PORT, 300)) {
                    L.have = 0;
                    Serial.printf("[NET] connected to node %d\n", L.peer);
                }
            }
        }
    }

    // Drain readable bytes from every link, assembling 8-byte frames.
    for (int i = 0; i < g_nlinks; ++i) {
        Link& L = g_links[i];
        while (L.cli.connected() && L.cli.available()) {
            L.buf[L.have++] = (uint8_t)L.cli.read();
            if (L.have == sizeof(Msg)) {
                Msg m; memcpy(&m, L.buf, sizeof(Msg));
                handle_msg(m);
                L.have = 0;
            }
        }
    }
}

static void wifi_init() {
    WiFi.mode(WIFI_STA);
    WiFi.config(node_ip(NODE_ID), IPAddress(NET_O1, NET_O2, NET_O3, 1),
                IPAddress(255, 255, 255, 0));
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.printf("[WiFi] connecting to \"%s\" as %s ...\n",
                  WIFI_SSID, node_ip(NODE_ID).toString().c_str());
    uint32_t t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print('.'); }
    Serial.println();
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[FATAL] WiFi connect failed — check SSID/PASS and subnet octets");
        while (true) delay(1000);
    }
    Serial.printf("[WiFi] connected, IP %s\n", WiFi.localIP().toString().c_str());

    g_server.begin();
    g_server.setNoDelay(true);

    // Set up the link table: connect out to every higher NODE_ID; the rest of
    // the slots are filled by incoming connections from lower NODE_IDs.
    g_nlinks = 0;
    for (int j = 1; j <= NUM_NODES; ++j)
        if (j > NODE_ID) { g_links[g_nlinks].outgoing = true; g_links[g_nlinks].peer = j; g_nlinks++; }
    for (int j = 1; j <= NUM_NODES; ++j)
        if (j < NODE_ID) { g_links[g_nlinks].outgoing = false; g_nlinks++; }
    Serial.printf("[NET] node %d  TCP port %d  links=%d\n", NODE_ID, TCP_PORT, g_nlinks);
}

// =============================================================================
// Distributed step helpers
// =============================================================================

// Apply all pending events received over the air, in gseq order, to our
// encrypted replica. Deduplicates via g_applied_gseq.
static void drain_events() {
    EvIn e;
    while (dequeue_event(&e)) {
        if (e.gseq <= g_applied_gseq) continue;             // already applied / stale
        if (e.gseq != g_applied_gseq + 1) {
            // A broadcast was missed. For this demo we log it; the token's gseq
            // (checked on receipt) lets the next actor detect being behind.
            Serial.printf("[WARN] gseq gap: have %u, got %u (packet loss)\n",
                          (unsigned)g_applied_gseq, (unsigned)e.gseq);
        }
        char nm[16]; strncpy_P(nm, (const char*)pgm_read_ptr(&EVENT_NAMES[e.ev]), 15); nm[15]=0;
        he_step(e.ev);
        g_applied_gseq = e.gseq;
        Serial.printf("[SYNC] applied %s (gseq %u) → buffer enables: a1=%d a2=%d a3=%d\n",
                      nm, (unsigned)e.gseq,
                      event_enabled(EV_A1), event_enabled(EV_A2), event_enabled(EV_A3));
    }
}

// =============================================================================
// Onboard RGB status LED (node identity + token + activity)
// =============================================================================
//
// D1 = blue, D2 = green, D3 = purple.  Dim = idle / no token; full brightness =
// this board currently holds the token; brief white flash = this board just
// fired an event. Uses the ESP32 core's rgbLedWrite() on the built-in
// addressable LED. Most ESP32-S3 devkits expose it as RGB_BUILTIN (GPIO48); if
// your board uses a different pin, override RGB_LED_PIN below.
#ifndef RGB_LED_PIN
  #ifdef RGB_BUILTIN
    #define RGB_LED_PIN RGB_BUILTIN
  #else
    #define RGB_LED_PIN 48
  #endif
#endif

static uint8_t LED_R = 0, LED_G = 0, LED_B = 0;   // this node's identity colour

// Identity colour for a given node: D1 blue, D2 green, D3 purple.
static void node_color(int node, uint8_t* r, uint8_t* g, uint8_t* b) {
    switch (node) {
        case 1: *r = 0;   *g = 0;   *b = 255; break;  // D1 blue
        case 2: *r = 0;   *g = 255; *b = 0;   break;  // D2 green
        case 3: *r = 160; *g = 0;   *b = 255; break;  // D3 purple
        default:*r = *g = *b = 0;
    }
}
static inline void led_rgb(uint8_t r, uint8_t g, uint8_t b) {
    rgbLedWrite(RGB_LED_PIN, r, g, b);
}
// Identity colour: bright while holding the token, dimmed (~1/6) otherwise.
static void led_identity(bool bright) {
    if (bright) led_rgb(LED_R, LED_G, LED_B);
    else        led_rgb(LED_R / 6, LED_G / 6, LED_B / 6);
}
// Show a specific node's colour (used in SOLO mode as roles take turns).
static void led_node(int node, bool bright) {
    uint8_t r, g, b; node_color(node, &r, &g, &b);
    if (bright) led_rgb(r, g, b);
    else        led_rgb(r / 6, g / 6, b / 6);
}
static void led_flash() {            // brief white flash when an event fires
    led_rgb(255, 255, 255);
    delay(60);
}
static void led_init() {
    node_color(NODE_ID, &LED_R, &LED_G, &LED_B);
    led_identity(false);             // identity colour, dim (idle, no token)
}

// Fire OUR buffer-changing event locally and broadcast it to the other boards.
static void fire_and_broadcast(int ev_gi) {
    uint32_t gseq = g_applied_gseq + 1;
    char nm[16]; strncpy_P(nm, (const char*)pgm_read_ptr(&EVENT_NAMES[ev_gi]), 15); nm[15]=0;
    he_step(ev_gi);                 // apply to our own replica
    g_applied_gseq = gseq;
    Msg m{ MSG_EVENT, (uint8_t)NODE_ID, 0, (uint8_t)ev_gi, gseq };
    send_msg(m);
    led_flash(); led_identity(true);            // white blip, then back to bright (still holding token)
    Serial.printf("[FIRE] %s (gseq %u) broadcast → buffer enables: a1=%d a2=%d a3=%d\n",
                  nm, (unsigned)gseq, event_enabled(EV_A1), event_enabled(EV_A2), event_enabled(EV_A3));
}

static void pass_token() {
    int next = (NODE_ID % NUM_NODES) + 1;
    Msg m{ MSG_TOKEN, (uint8_t)NODE_ID, (uint8_t)next, 0xFF, g_applied_gseq };
    send_msg(m);
    g_have_token = false;
    led_identity(false);                        // released the token → dim identity
    Serial.printf("[TOKEN] → node %d (gseq %u)\n\n", next, (unsigned)g_applied_gseq);
}

// One UAV duty cycle while we hold the token. Returns after the trip completes.
static void run_uav_turn() {
    drain_events();
    led_identity(true);                         // holding the token → bright identity

    // Safety: if the token says more events happened than we've applied, we are
    // behind (a broadcast was lost). Skip acting this turn to avoid acting on a
    // stale buffer level; we resync as events arrive.
    if (g_applied_gseq < g_token_gseq) {
        Serial.printf("[HOLD] behind (have %u < token %u) — passing without acting\n",
                      (unsigned)g_applied_gseq, (unsigned)g_token_gseq);
        delay(IDLE_HOLD_MS);
        pass_token();
        return;
    }

    bool enabled = event_enabled(ROLE.gate_gi);
    if (!enabled || !g_uav_idle) {
        char gate[16]; strncpy_P(gate, (const char*)pgm_read_ptr(&EVENT_NAMES[ROLE.gate_gi]), 15); gate[15]=0;
        Serial.printf("[HOLD] %s idle=%d  gate(%s)=%d — %s\n",
                      ROLE.uav, g_uav_idle, gate, enabled,
                      enabled ? "UAV still flying" : "buffer blocks action");
        delay(IDLE_HOLD_MS);
        pass_token();
        return;
    }

    // Readiness gate (models autonomous availability; prevents consumer starvation).
    if ((int)(esp_random() % 100) >= READY_PCT) {
        Serial.printf("[HOLD] %s ready-check failed this turn — passing\n", ROLE.uav);
        delay(IDLE_HOLD_MS);
        pass_token();
        return;
    }

    g_uav_idle = false;
    if (ROLE.emit_after_flight) {
        // Producer D1: take off (a1, no buffer change) → fly → deposit (b1, +1).
        Serial.printf("[%s] take-off (a1) — flying to buffer...\n", ROLE.uav);
        delay(FLIGHT_MS);
        fire_and_broadcast(ROLE.buf_gi);          // b1 deposits → B+1
        Serial.printf("[%s] deposited package in buffer.\n", ROLE.uav);
    } else {
        // Consumer D2/D3: pick up (a2/a3, −1) → fly → deliver (b2/b3).
        fire_and_broadcast(ROLE.buf_gi);          // a2/a3 pickup → B−1
        Serial.printf("[%s] picked up from buffer — flying to client...\n", ROLE.uav);
        delay(FLIGHT_MS);
        Serial.printf("[%s] delivered to client.\n", ROLE.uav);
    }
    g_uav_idle = true;
    pass_token();
}

#if SOLO_TEST
// One full UAV cycle for `node`, acting on the single shared replica — no
// ESP-NOW, no token. The loop calls this for node 1, 2, 3 in turn so a single
// board exercises the whole warehouse → B → client pipeline.
static void solo_turn(int node) {
    const Role& r = ROLES[node];
    led_node(node, true);                         // colour of the UAV taking its turn
    char gate[16]; strncpy_P(gate, (const char*)pgm_read_ptr(&EVENT_NAMES[r.gate_gi]), 15); gate[15]=0;

    if (!event_enabled(r.gate_gi)) {
        Serial.printf("[HOLD] %s gate(%s) disabled — buffer blocks action\n", r.uav, gate);
        delay(IDLE_HOLD_MS); led_node(node, false); return;
    }
    if ((int)(esp_random() % 100) >= READY_PCT) {
        Serial.printf("[HOLD] %s not ready this turn\n", r.uav);
        delay(IDLE_HOLD_MS); led_node(node, false); return;
    }

    if (r.emit_after_flight) {                     // D1: take off → fly → deposit (+1)
        Serial.printf("[%s] take-off (a1) — flying to buffer...\n", r.uav);
        delay(FLIGHT_MS);
        he_step(r.buf_gi); g_applied_gseq++;
        led_flash(); led_node(node, true);
        Serial.printf("[FIRE] b1 (gseq %u) → buffer enables: a1=%d a2=%d a3=%d\n",
                      (unsigned)g_applied_gseq, event_enabled(EV_A1), event_enabled(EV_A2), event_enabled(EV_A3));
        Serial.printf("[%s] deposited package in buffer.\n", r.uav);
    } else {                                       // D2/D3: pick up (−1) → fly → deliver
        char ev[16]; strncpy_P(ev, (const char*)pgm_read_ptr(&EVENT_NAMES[r.buf_gi]), 15); ev[15]=0;
        he_step(r.buf_gi); g_applied_gseq++;
        led_flash(); led_node(node, true);
        Serial.printf("[FIRE] %s (gseq %u) → buffer enables: a1=%d a2=%d a3=%d\n",
                      ev, (unsigned)g_applied_gseq, event_enabled(EV_A1), event_enabled(EV_A2), event_enabled(EV_A3));
        Serial.printf("[%s] picked up from buffer — flying to client...\n", r.uav);
        delay(FLIGHT_MS);
        Serial.printf("[%s] delivered to client.\n", r.uav);
    }
    led_node(node, false);
}
#endif  // SOLO_TEST

// =============================================================================
// Setup / loop
// =============================================================================

void setup() {
    Serial.begin(115200);
    delay(1500);
    led_init();                                 // show this board's identity colour immediately
    Serial.println("\n============================================");
#if SOLO_TEST
    Serial.println("  Homomorphic DES — SOLO TEST (D1+D2+D3 on one board, no network)");
#else
    Serial.printf ("  Distributed Homomorphic DES — UAV %s (node %d)\n", ROLE.uav, NODE_ID);
#endif
    Serial.println("============================================");

    crypto_init();
#if !SOLO_TEST
    wifi_init();
#endif

    // Replicate the shared buffer supervisor (reduced, smallest) on every board.
    Serial.println("[INIT] loading shared buffer supervisor (encrypted replica)...");
    load_supervisors(LMOD_RED_SUPS, LMOD_RED_COUNT);
    if (!init_states()) { Serial.println("[FATAL] encryption failed"); while (true) delay(1000); }
    warm_cache();
    Serial.printf("[INIT] ready. buffer enables: a1=%d a2=%d a3=%d (empty: a2/a3 disabled)\n\n",
                  event_enabled(EV_A1), event_enabled(EV_A2), event_enabled(EV_A3));

#if !SOLO_TEST
    // Let the TCP mesh come up before anyone acts (so the first token/event
    // isn't sent into a not-yet-connected link).
    Serial.println("[NET] waiting for peer links...");
    uint32_t t0 = millis();
    while (millis() - t0 < 10000) {
        net_poll();
        int up = 0; for (int i = 0; i < g_nlinks; ++i) if (g_links[i].cli.connected()) up++;
        if (up == g_nlinks) { Serial.println("[NET] all peer links up"); break; }
        delay(50);
    }
    // Node 1 starts holding the token.
    if (NODE_ID == 1) { g_have_token = true; g_token_gseq = 0; }
#endif
}

void loop() {
#if SOLO_TEST
    for (int node = 1; node <= NUM_NODES; ++node) solo_turn(node);
    delay(300);
#else
    net_poll();                      // accept/reconnect peers, read incoming Msgs
    drain_events();                  // keep replica synced even without the token
    if (g_have_token) run_uav_turn();
    else              delay(10);
#endif
}
