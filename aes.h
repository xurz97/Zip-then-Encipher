// AES template
#define MAX_KEY_BYTES 16
#include <wmmintrin.h>
#include <smmintrin.h>
typedef unsigned char u8;

typedef struct
{
    __m128i rd_key[7 + MAX_KEY_BYTES / 4];
} AES_KEY;
#define AES_ROUNDS(_key) (10)

static __m128i assist128(__m128i a, __m128i b)
{
    __m128i tmp = _mm_slli_si128(a, 0x04);
    a = _mm_xor_si128(a, tmp);
    tmp = _mm_slli_si128(tmp, 0x04);
    a = _mm_xor_si128(_mm_xor_si128(a, tmp), _mm_slli_si128(tmp, 0x04));
    return _mm_xor_si128(a, _mm_shuffle_epi32(b, 0xff));
}

static void AES_set_encrypt_key(const unsigned char *userKey,
                                const int bits, AES_KEY *key)
{
    __m128i *sched = key->rd_key;
    (void)bits; /* Supress "unused" warning */
    sched[0] = _mm_loadu_si128((__m128i *)userKey);
    sched[1] = assist128(sched[0], _mm_aeskeygenassist_si128(sched[0], 0x1));
    sched[2] = assist128(sched[1], _mm_aeskeygenassist_si128(sched[1], 0x2));
    sched[3] = assist128(sched[2], _mm_aeskeygenassist_si128(sched[2], 0x4));
    sched[4] = assist128(sched[3], _mm_aeskeygenassist_si128(sched[3], 0x8));
    sched[5] = assist128(sched[4], _mm_aeskeygenassist_si128(sched[4], 0x10));
    sched[6] = assist128(sched[5], _mm_aeskeygenassist_si128(sched[5], 0x20));
    sched[7] = assist128(sched[6], _mm_aeskeygenassist_si128(sched[6], 0x40));
    sched[8] = assist128(sched[7], _mm_aeskeygenassist_si128(sched[7], 0x80));
    sched[9] = assist128(sched[8], _mm_aeskeygenassist_si128(sched[8], 0x1b));
    sched[10] = assist128(sched[9], _mm_aeskeygenassist_si128(sched[9], 0x36));
}

static void AES_NI_set_decrypt_key(__m128i *dkey, const __m128i *ekey)
{
    int i;
    dkey[10] = ekey[0];
    for (i = 1; i <= 9; i++)
        dkey[10 - i] = _mm_aesimc_si128(ekey[i]);
    dkey[0] = ekey[10];
}

static inline void AES_encrypt(const unsigned char *in,
                               unsigned char *out, const AES_KEY *key)
{
    int j;
    const __m128i *sched = ((__m128i *)(key->rd_key));
    __m128i tmp = _mm_load_si128((__m128i *)in);
    tmp = _mm_xor_si128(tmp, sched[0]);
    for (j = 1; j < AES_ROUNDS(*key); j++)
        tmp = _mm_aesenc_si128(tmp, sched[j]);
    tmp = _mm_aesenclast_si128(tmp, sched[j]);
    _mm_store_si128((__m128i *)out, tmp);
}

static inline void AES_decrypt(const unsigned char *in,
                               unsigned char *out, const AES_KEY *key)
{
    int j;
    const __m128i *sched = ((__m128i *)(key->rd_key));
    __m128i tmp = _mm_load_si128((__m128i *)in);
    tmp = _mm_xor_si128(tmp, sched[0]);
    for (j = 1; j < AES_ROUNDS(*key); j++)
        tmp = _mm_aesdec_si128(tmp, sched[j]);
    tmp = _mm_aesdeclast_si128(tmp, sched[j]);
    _mm_store_si128((__m128i *)out, tmp);
}