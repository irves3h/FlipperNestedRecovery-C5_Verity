#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "library.h"
#include "crapto1.h"
#include "parity.h"
#include "progress.h"

static int compare_uint64(const void *a, const void *b) {
    if (*(uint64_t *) b == *(uint64_t *) a) return 0;
    if (*(uint64_t *) b < *(uint64_t *) a) return 1;
    return -1;
}

// create the intersection (common members) of two sorted lists. Lists are terminated by -1. Result will be in list1. Number of elements is returned.
static uint32_t intersection(uint64_t *listA, uint64_t *listB) {
    if (listA == NULL || listB == NULL)
        return 0;

    uint64_t *p1, *p2, *p3;
    p1 = p3 = listA;
    p2 = listB;

    while (*p1 != UINT64_MAX && *p2 != UINT64_MAX) {
        if (compare_uint64(p1, p2) == 0) {
            *p3++ = *p1++;
            p2++;
        } else {
            while (compare_uint64(p1, p2) < 0) ++p1;
            while (compare_uint64(p1, p2) > 0) ++p2;
        }
    }
    *p3 = UINT64_MAX;
    return p3 - listA;
}

static int compare_16bits(const void *a, const void *b) {
    if ((*(uint64_t *) b & 0x00ff000000ff0000) == (*(uint64_t *) a & 0x00ff000000ff0000)) return 0;
    if ((*(uint64_t *) b & 0x00ff000000ff0000) > (*(uint64_t *) a & 0x00ff000000ff0000)) return 1;
    return -1;
}

static int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, const uint8_t *parity) {
    return ((oddparity8((Nt >> 24) & 0xFF) == ((parity[0]) ^ oddparity8((NtEnc >> 24) & 0xFF) ^ BIT(Ks1, 16))) && \
               (oddparity8((Nt >> 16) & 0xFF) == ((parity[1]) ^ oddparity8((NtEnc >> 16) & 0xFF) ^ BIT(Ks1, 8))) && \
               (oddparity8((Nt >> 8) & 0xFF) == ((parity[2]) ^ oddparity8((NtEnc >> 8) & 0xFF) ^ BIT(Ks1, 0)))) ? 1 : 0;
}

static uint32_t pow_calc(uint32_t num, uint32_t deg) {
    uint32_t result = 1;

    for (long i = 0; i < deg; i++) {
        result *= num;
    }

    return result;
}

static uint8_t *decode_parity(uint32_t parity) {
    uint8_t *par_array = malloc(sizeof(uint8_t) * 4);

    for (int j = 3; j >= 0; j--) {
        if (j) {
            par_array[3 - j] = (parity / pow_calc(10, j));
        } else {
            par_array[3 - j] = parity;
        }

        parity -= (parity / pow_calc(10, j)) * pow_calc(10, j);
    }

    return par_array;
}

// NG-C4 (P3): one-list + direct verify.
// Instead of building two lfsr_recovery32 tables and intersecting them,
// build only list0 (nonce 0), roll each state back to the key state and
// verify it directly against nonce 1: crypto1_word(K, nt1'^uid, 0) == ks1'.
// The verify predicate defines EXACTLY the set rollback(list1), so the
// returned key set is identical to the two-list intersection (proved by
// c-exp/verify-test/test_verify.c on the known key + 100k random cases for
// the early-exit bit order). Sorting / merging / intersection are skipped.
// Per-call saving: one lfsr_recovery32 (~312ms) + sorts/merge (~41ms);
// added cost: rollback-all (~13ms) + early-exit verify-all (~1ms).
static bool verify_key_early(struct Crypto1State *st, uint32_t in, uint32_t expect) {
    // Bit-for-bit replica of crypto1_word(st, in, 0) with early exit.
    for (int j = 0; j < 32; j++) {
        uint8_t b = crypto1_bit(st, BEBIT(in, j), 0);
        if (b != ((expect >> (24 ^ j)) & 1)) return false;
    }
    return true;
}

static bool nested_calculate(InfoList_t *arg) {
    InfoList_t *info = arg;
    struct Crypto1State *list0;
    uint32_t len0 = 0;

    list0 = lfsr_recovery32(info->ks0, info->nt0 ^ info->uid);
    for (struct Crypto1State *q = list0; q->odd | q->even; q++) len0++;

    bool found = false;
    if (!info->free) {
        // Collect mode: gather the verifying rolled-back STATES and sort
        // them by raw state uint64 (the old qsort64+intersection order),
        // then extract keys in that order. Do NOT sort by extracted key
        // value: crypto1_get_lfsr is a bit permutation (BIT(odd/even, i^3)
        // interleaved), so key-ascending order differs from the original
        // output order (test_calculate_full caught exactly this).
        // qsort with compare_uint64 reads each 8-byte Crypto1State as a
        // uint64, same as the original's keyhead union overlay.
        struct Crypto1State found_states[256];
        uint32_t nfound = 0;
        for (uint32_t i = 0; i < len0; i++) {
            struct Crypto1State k = list0[i];
            lfsr_rollback_word(&k, info->nt0 ^ info->uid, 0);
            struct Crypto1State v = k;
            if (verify_key_early(&v, info->nt1 ^ info->uid, info->ks1)) {
                if (nfound < 256) found_states[nfound++] = k;
            }
        }
        qsort(found_states, nfound, sizeof(struct Crypto1State), compare_uint64);
        for (uint32_t i = 0; i < nfound; i++) {
            uint64_t key64 = 0;
            char ch[14];
            crypto1_get_lfsr(&found_states[i], &key64);
            snprintf(ch, 14, "%012" PRIx64 ";", key64);
            strncat(info->keys, ch, 13);
        }
        found = (nfound > 0);
    } else {
        // Probe mode: stop at the first verifying state.
        for (uint32_t i = 0; i < len0; i++) {
            struct Crypto1State k = list0[i];
            lfsr_rollback_word(&k, info->nt0 ^ info->uid, 0);
            struct Crypto1State v = k;
            if (verify_key_early(&v, info->nt1 ^ info->uid, info->ks1)) { found = true; break; }
        }
    }

    free(list0);
    return found;
}

static void *nested_wrapper(void *arg) {
    bool run = nested_calculate(arg);
    free(arg);
    if (run) {
        return (void *) 1;
    } else {
        return 0;
    }
}

char *run_nested(uint32_t uid, uint32_t nt0, uint32_t ks0, uint32_t nt1, uint32_t ks1) {
    InfoList_t *info = malloc(sizeof(InfoList_t));
    info->uid = uid;
    info->nt0 = nt0;
    info->ks0 = ks0;
    info->nt1 = nt1;
    info->ks1 = ks1;
    info->keys = calloc(256, sizeof(char) * 14);
    info->free = false;
    nested_calculate(info);
    return info->keys;
}

char *
run_full_nested(uint32_t uid, uint32_t nt0, uint32_t ks0, uint32_t par0, uint32_t nt1, uint32_t ks1, uint32_t par1,
                int from, int to, bool progress) {
    // NG-C5 (combined): per-first shared list0 + rollback-once + direct verify.
    // For a fixed `first`, nt0' (hence list0) is identical for all candidate
    // seconds, so list0 is built once per first and rolled back once; each
    // candidate second is then checked by direct verify against the shared
    // rolled-back list (no second table, no sorts, no intersection, no threads).
    // The winning second is the LAST matching one (same as C0's join order),
    // and collected keys follow C0's qsort64+intersection order (rolled-back
    // states sorted by raw state uint64 ascending, NOT by key value).
    uint32_t range = (uint32_t)(to - from);
    uint32_t *seconds = malloc((range ? range : 1) * sizeof(uint32_t));
    if (!seconds) return calloc(1, 1);

    for (int first = from; first < to; first++) {
        if (progress) print_progress(first - from, to - from);
        uint32_t nsec = 0;
        uint32_t nt0p = prng_successor(nt0, first);
        uint8_t *par0_decoded = decode_parity(par0);
        uint8_t *par1_decoded = decode_parity(par1);
        for (int second = from; second < to; second++) {
            uint32_t nt1p = prng_successor(nt1, second);
            if (!valid_nonce(nt0p, ks0, ks0 ^ nt0p, par0_decoded) ||
                !valid_nonce(nt1p, ks1, ks1 ^ nt1p, par1_decoded)) {
                continue;
            }
            seconds[nsec++] = (uint32_t)second;
        }
        free(par0_decoded);
        free(par1_decoded);
        if (nsec == 0) continue;

        // Build list0 once for this first, roll it back once.
        struct Crypto1State *list0 = lfsr_recovery32(ks0 ^ nt0p, nt0p ^ uid);
        uint32_t len0 = 0;
        for (struct Crypto1State *q = list0; q->odd | q->even; q++) len0++;
        struct Crypto1State *rolled = malloc((len0 ? len0 : 1) * sizeof(struct Crypto1State));
        for (uint32_t i = 0; i < len0; i++) {
            rolled[i] = list0[i];
            lfsr_rollback_word(&rolled[i], nt0p ^ uid, 0);
        }
        free(list0);

        // Find the LAST passing second whose keystream verifies.
        int found_second = -1;
        for (uint32_t s = 0; s < nsec; s++) {
            uint32_t nt1p = prng_successor(nt1, seconds[s]);
            uint32_t ks1p = ks1 ^ nt1p;
            for (uint32_t i = 0; i < len0; i++) {
                struct Crypto1State v = rolled[i];
                if (verify_key_early(&v, nt1p ^ uid, ks1p)) { found_second = (int)seconds[s]; break; }
            }
        }
        if (found_second < 0) { free(rolled); continue; }

        // Collect all keys for the winning second, in the original order:
        // verifying rolled-back states sorted by raw state uint64 (the old
        // qsort64+intersection order), NOT by extracted key value.
        uint32_t nt1p = prng_successor(nt1, found_second);
        uint32_t ks1p = ks1 ^ nt1p;
        struct Crypto1State found_states[256];
        uint32_t nfound = 0;
        for (uint32_t i = 0; i < len0; i++) {
            struct Crypto1State v = rolled[i];
            if (verify_key_early(&v, nt1p ^ uid, ks1p)) {
                if (nfound < 256) found_states[nfound++] = rolled[i];
            }
        }
        free(rolled);
        free(seconds);
        qsort(found_states, nfound, sizeof(struct Crypto1State), compare_uint64);
        char *keys = calloc(256, sizeof(char) * 14);
        for (uint32_t i = 0; i < nfound; i++) {
            uint64_t key64 = 0;
            char ch[14];
            crypto1_get_lfsr(&found_states[i], &key64);
            snprintf(ch, 14, "%012" PRIx64 ";", key64);
            strncat(keys, ch, 13);
        }
        if (progress) exit_progress();
        return keys;
    }

    free(seconds);
    if (progress) exit_progress();
    return calloc(1, 1);
}