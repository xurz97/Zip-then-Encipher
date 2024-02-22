#include "ae.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include <stdio.h>
#include "lz4.h"
// multiply by 2, from PyCryptodome
static __m128i multx(__m128i a)
{
    int msb;
    int64_t r;
    uint64_t p0, p1;
    __m128i t0, t1, t2, t3, t4, t5, t6, t7;
    msb = _mm_movemask_epi8(a) >> 15;          /* Bit 0 is a[127] */
    r = (msb ^ 1) - 1;                         /* MSB is copied into all 64 positions */
    p0 = (uint64_t)r & 0x0000000000000001U;    /* Zero or XOR mask (low) */
    p1 = (uint64_t)r & ((uint64_t)0xc2 << 56); /* Zero or XOR mask (high) */
    t0 = _mm_loadl_epi64((__m128i *)&p0);
    t1 = _mm_loadl_epi64((__m128i *)&p1);
    t2 = _mm_unpacklo_epi64(t0, t1); /* Zero or XOR mask */
    /* Shift value a left by 1 bit */
    t3 = _mm_slli_si128(a, 8);   /* Shift a left by 64 bits (lower 64 bits are zero) */
    t4 = _mm_srli_epi64(t3, 63); /* Bit 64 is now a[63], all other bits are 0 */
    t5 = _mm_slli_epi64(a, 1);   /* Shift left by 1 bit, but bit 64 is zero, not a[63] */
    t6 = _mm_or_si128(t4, t5);   /* Actual result of shift left by 1 bit */
    /* XOR conditional mask */
    t7 = _mm_xor_si128(t2, t6);
    return t7;
}

static inline void gfmul(__m128i a, __m128i b, __m128i *res)
{
    const uint64_t c2 = (uint64_t)0xc2 << 56;
    __m128i POLY = _mm_loadl_epi64((__m128i *)&c2);
    __m128i tmp1, tmp2, tmp3, tmp4;
    tmp1 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp2 = _mm_clmulepi64_si128(a, b, 0x11);
    tmp3 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp3 = _mm_xor_si128(tmp4, tmp3);
    tmp4 = _mm_slli_si128(tmp3, 8);
    tmp3 = _mm_srli_si128(tmp3, 8);
    tmp1 = _mm_xor_si128(tmp4, tmp1);
    tmp4 = _mm_xor_si128(tmp3, tmp2);
    /* Montgomery reduction */
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78); // 78 = 01001110b
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78); // 78 = 01001110b
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    *res = _mm_xor_si128(tmp1, tmp4);
}
// multiply used in reduce8
static void multiply(__m128i H1, __m128i H2, __m128i H3, __m128i H4,
                     __m128i X1, __m128i X2, __m128i X3, __m128i X4,
                     __m128i *hi, __m128i *lo)
{
    __m128i H1_X1_lo, H1_X1_hi,
        H2_X2_lo, H2_X2_hi,
        H3_X3_lo, H3_X3_hi,
        H4_X4_lo, H4_X4_hi;
    __m128i tmp0, tmp1, tmp2, tmp3;
    __m128i tmp4, tmp5, tmp6, tmp7;
    __m128i tmp8, tmp9;
    H1_X1_lo = _mm_clmulepi64_si128(H1, X1, 0x00);
    H2_X2_lo = _mm_clmulepi64_si128(H2, X2, 0x00);
    H3_X3_lo = _mm_clmulepi64_si128(H3, X3, 0x00);
    H4_X4_lo = _mm_clmulepi64_si128(H4, X4, 0x00);
    *lo = _mm_xor_si128(H1_X1_lo, H2_X2_lo);
    *lo = _mm_xor_si128(*lo, H3_X3_lo);
    *lo = _mm_xor_si128(*lo, H4_X4_lo);
    H1_X1_hi = _mm_clmulepi64_si128(H1, X1, 0x11);
    H2_X2_hi = _mm_clmulepi64_si128(H2, X2, 0x11);
    H3_X3_hi = _mm_clmulepi64_si128(H3, X3, 0x11);
    H4_X4_hi = _mm_clmulepi64_si128(H4, X4, 0x11);
    *hi = _mm_xor_si128(H1_X1_hi, H2_X2_hi);
    *hi = _mm_xor_si128(*hi, H3_X3_hi);
    *hi = _mm_xor_si128(*hi, H4_X4_hi);
    tmp0 = _mm_shuffle_epi32(H1, 78);
    tmp4 = _mm_shuffle_epi32(X1, 78);
    tmp0 = _mm_xor_si128(tmp0, H1);
    tmp4 = _mm_xor_si128(tmp4, X1);
    tmp1 = _mm_shuffle_epi32(H2, 78);
    tmp5 = _mm_shuffle_epi32(X2, 78);
    tmp1 = _mm_xor_si128(tmp1, H2);
    tmp5 = _mm_xor_si128(tmp5, X2);
    tmp2 = _mm_shuffle_epi32(H3, 78);
    tmp6 = _mm_shuffle_epi32(X3, 78);
    tmp2 = _mm_xor_si128(tmp2, H3);
    tmp6 = _mm_xor_si128(tmp6, X3);
    tmp3 = _mm_shuffle_epi32(H4, 78);
    tmp7 = _mm_shuffle_epi32(X4, 78);
    tmp3 = _mm_xor_si128(tmp3, H4);
    tmp7 = _mm_xor_si128(tmp7, X4);
    tmp0 = _mm_clmulepi64_si128(tmp0, tmp4, 0x00);
    tmp1 = _mm_clmulepi64_si128(tmp1, tmp5, 0x00);
    tmp2 = _mm_clmulepi64_si128(tmp2, tmp6, 0x00);
    tmp3 = _mm_clmulepi64_si128(tmp3, tmp7, 0x00);
    tmp0 = _mm_xor_si128(tmp0, *lo);
    tmp0 = _mm_xor_si128(tmp0, *hi);
    tmp0 = _mm_xor_si128(tmp1, tmp0);
    tmp0 = _mm_xor_si128(tmp2, tmp0);
    tmp0 = _mm_xor_si128(tmp3, tmp0);
    tmp4 = _mm_slli_si128(tmp0, 8);
    tmp0 = _mm_srli_si128(tmp0, 8);
    *lo = _mm_xor_si128(tmp4, *lo);
    *hi = _mm_xor_si128(tmp0, *hi);
}

static void reduce8(__m128i H1, __m128i H2, __m128i H3, __m128i H4, __m128i H5, __m128i H6, __m128i H7, __m128i H8,
                    __m128i X1, __m128i X2, __m128i X3, __m128i X4, __m128i X5, __m128i X6, __m128i X7, __m128i X8, __m128i *res)
{

    const uint64_t c2 = (uint64_t)0xc2 << 56;
    __m128i POLY = _mm_loadl_epi64((__m128i *)&c2);
    __m128i lo1, hi1, lo, hi;
    __m128i tmp1, tmp2, tmp3, tmp4;
    multiply(H1, H2, H3, H4, X1, X2, X3, X4, &hi1, &lo1);
    multiply(H5, H6, H7, H8, X5, X6, X7, X8, &hi, &lo);
    tmp1 = _mm_xor_si128(lo, lo1);
    tmp4 = _mm_xor_si128(hi, hi1);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78);
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    tmp2 = _mm_clmulepi64_si128(tmp1, POLY, 0x00);
    tmp3 = _mm_shuffle_epi32(tmp1, 78);
    tmp1 = _mm_xor_si128(tmp2, tmp3);
    *res = _mm_xor_si128(tmp1, tmp4);
    return;
}
// from Intel GCM Whitepaper
static void gfmul1(__m128i a, __m128i b, __m128i *res)
{
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);
    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);
    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);
    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    tmp6 = _mm_xor_si128(tmp6, tmp3);
    *res = tmp6;
}
#define ALIGN(n) __attribute__((aligned(n)))
void HCTR_encrypt(const unsigned char *pt,
                  unsigned char *ct,
                  const unsigned char *tweak,
                  int pt_len,
                  ae_ctx *ctx);
void HCTR_decrypt(const unsigned char *ct,
                  unsigned char *pt,
                  const unsigned char *tweak,
                  int ct_len,
                  ae_ctx *ctx);
void HCTR_encrypt_8(const unsigned char *pt,
                  unsigned char *ct,
                  const unsigned char *tweak,
                  int pt_len,
                  ae_ctx *ctx);


int ae_init(ae_ctx *ctx,
            const u8 *key,
            int key_len,
            int nonce_len,
            int tag_len)
{
    u8 key1[16];
    for (int i = 0; i < 16; i++)
        key1[i] = key[i];
    for (int i = 0; i < 16; i++)
        ctx->key2[i] = key[i + 16];
    AES_set_encrypt_key((const u8 *)key1, (AES_KEY *)ctx->KEY);
    AES_NI_set_decrypt_key((__m128i *)ctx->KEY2, (__m128i *)ctx->KEY);
    return 0;
}
void output2(unsigned char *arr, int num)
{
    for (int i = 0; i < num; i++)
    {
        printf("%02x", arr[i]);
        if (i % 16 == 15)
            printf("\n");
    }
}
int ae_encrypt(ae_ctx *ctx,
               const u8 *nonce,
               const u8 *pt,
               int pt_len,
               u8 *ct,
               int *iszip)
{
    //尝试压缩
    int maxCompressedSize = LZ4_compressBound(pt_len);
    u8 compressedData[8192];
    // 压缩数据
    int outputLen = LZ4_compress_default(
        (const char*)(pt),
        (char*)(compressedData),
        pt_len,
        maxCompressedSize);
    //printf("pt_len = %d\n",pt_len);
    //printf("outputLen = %d\n",outputLen);
    int space = pt_len-outputLen;
    //printf("space = %d\n",space);
    if(space<24){
        HCTR_encrypt_8(pt, ct, nonce, pt_len, ctx);
        *iszip = 0; // no zip
        return pt_len;
    }
    //printf("space=%d\n",space);
    ((uint64_t*)ct)[0]=123;
    ((uint64_t*)ct)[1]=0;
    u8 tempNonce[16];
    ((uint64_t*)tempNonce)[0]=((uint64_t*)nonce)[0];
    ((uint64_t*)tempNonce)[1]=((uint64_t*)ct)[0];
    for(int i=outputLen;i<pt_len-8;i++) compressedData[i]=0;
    //output2(compressedData,pt_len-8);
    u8* newct=&ct[16];
    HCTR_encrypt_8(compressedData, newct, tempNonce, pt_len-16, ctx);
    *iszip = 1;
    return outputLen;
}

void HCTR_encrypt(const unsigned char *pt,
                  unsigned char *ct,
                  const unsigned char *tweak,
                  int pt_len,
                  ae_ctx *ctx)
{
    __m128i Z1 = _mm_loadu_si128((__m128i *)pt), Z2 = _mm_setzero_si128();
    __m128i D = _mm_setzero_si128(), hash2 = _mm_setzero_si128();
    __m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
    __m128i ctr = _mm_setzero_si128();
    __m128i tmp1 = _mm_setzero_si128(), ciphertext = _mm_setzero_si128(), Z1Z2 = _mm_setzero_si128();
    __m128i H = _mm_loadu_si128((__m128i *)ctx->key2);
    H = _mm_shuffle_epi8(H, BSWAP_MASK);
    H = multx(H);
    __m128i lenswap = _mm_setzero_si128();
    lenswap = _mm_insert_epi64(lenswap, pt_len * 8, 0);
    // Hash1
    for (int i = 1; i < (pt_len >> 4); i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H, &D);
    }
    tmp1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)tweak), BSWAP_MASK);
    D = _mm_xor_si128(D, tmp1);
    gfmul(D, H, &D);
    D = _mm_xor_si128(D, lenswap);
    gfmul(D, H, &D);
    D = _mm_shuffle_epi8(D, BSWAP_MASK);
    Z1 = _mm_xor_si128(Z1, D);
    __m128i *KEY = (__m128i *)ctx->KEY;
    tmp1 = _mm_xor_si128(Z1, KEY[0]);
    for (int i = 1; i < 10; i++)
        tmp1 = _mm_aesenc_si128(tmp1, KEY[i]);
    Z2 = _mm_aesenclast_si128(tmp1, KEY[10]);
    // CTR mode
    Z1Z2 = _mm_xor_si128(Z1, Z2);
    ctr = _mm_add_epi64(ctr, ONE);
    for (int i = 1; i < pt_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr, BSWAP_EPI64);
        ctr = _mm_add_epi64(ctr, ONE);
        tmp1 = _mm_xor_si128(Z1Z2, tmp1);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        for (int j = 1; j < 10; j++)
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
        ciphertext = _mm_aesenclast_si128(tmp1, KEY[10]);
        ciphertext = _mm_xor_si128(ciphertext, _mm_loadu_si128(&((__m128i *)pt)[i]));
        _mm_storeu_si128(&((__m128i *)ct)[i], ciphertext);
        ciphertext = _mm_shuffle_epi8(ciphertext, BSWAP_MASK);
        hash2 = _mm_xor_si128(hash2, ciphertext);
        gfmul(hash2, H, &hash2);
    }
    tmp1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)tweak), BSWAP_MASK);
    hash2 = _mm_xor_si128(hash2, tmp1);
    gfmul(hash2, H, &hash2);
    hash2 = _mm_xor_si128(hash2, lenswap);
    gfmul(hash2, H, &hash2);
    hash2 = _mm_shuffle_epi8(hash2, BSWAP_MASK);
    ciphertext = _mm_xor_si128(Z2, hash2);
    _mm_storeu_si128(&((__m128i *)ct)[0], ciphertext);
}

int ischeck(u8 *pt,int start,int end){
    for(int i=start;i<end;i++){
        if(pt[i]!=0) return -1;
    }
   
    return 0;
}

int ae_decrypt(ae_ctx *ctx,
               const u8 *nonce,
               const u8 *ct,
               int ct_len,
               u8 *pt,
               int iszip,
               int zip_len)
{
    if(iszip==0) {HCTR_decrypt(ct, pt, nonce, ct_len, ctx);return ct_len;}
    u8 tempNonce[16];
    ((uint64_t*)tempNonce)[0]=((uint64_t*)nonce)[0];
    ((uint64_t*)tempNonce)[1]=((uint64_t*)ct)[0];
    u8 compressedData[4096];
    HCTR_decrypt(ct+16, compressedData, tempNonce, ct_len-16, ctx);
    if(ischeck(compressedData,zip_len,ct_len-16)) return -1;//验证失败
    int decompressedSize = LZ4_decompress_safe(
        (const char*)(compressedData),
        (char*)(pt),
        zip_len,
        ct_len);
    if (decompressedSize < 0) {
        return -2;//解谜失败
    }
    return ct_len;
}
void HCTR_decrypt(const unsigned char *ct,
                  unsigned char *pt,
                  const unsigned char *tweak,
                  int ct_len,
                  ae_ctx *ctx)
{
    __m128i Z1 = _mm_loadu_si128((__m128i *)ct), Z2 = _mm_setzero_si128();
    __m128i D = _mm_setzero_si128(), hash2 = _mm_setzero_si128();
    __m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
    __m128i ctr = _mm_setzero_si128();
    __m128i tmp1 = _mm_setzero_si128(), ciphertext = _mm_setzero_si128(), Z1Z2 = _mm_setzero_si128();
    __m128i H = _mm_loadu_si128((__m128i *)ctx->key2);
    H = _mm_shuffle_epi8(H, BSWAP_MASK);
    H = multx(H);
    __m128i lenswap = _mm_setzero_si128();
    lenswap = _mm_insert_epi64(lenswap, ct_len * 8, 0);
    // Hash1
    for (int i = 1; i < (ct_len >> 4); i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)ct)[i]), BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H, &D);
    }
    tmp1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)tweak), BSWAP_MASK);
    D = _mm_xor_si128(D, tmp1);
    gfmul(D, H, &D);
    D = _mm_xor_si128(D, lenswap);
    gfmul(D, H, &D);
    D = _mm_shuffle_epi8(D, BSWAP_MASK);
    Z1 = _mm_xor_si128(Z1, D);
    __m128i *KEY = (__m128i *)ctx->KEY2;
    tmp1 = _mm_xor_si128(Z1, KEY[0]);
    for (int i = 1; i < 10; i++)
        tmp1 = _mm_aesdec_si128(tmp1, KEY[i]);
    Z2 = _mm_aesdeclast_si128(tmp1, KEY[10]);
    // CTR mode
    Z1Z2 = _mm_xor_si128(Z1, Z2);
    ctr = _mm_add_epi64(ctr, ONE);
    KEY = (__m128i *)ctx->KEY;
    for (int i = 1; i < ct_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr, BSWAP_EPI64);
        ctr = _mm_add_epi64(ctr, ONE);
        tmp1 = _mm_xor_si128(Z1Z2, tmp1);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        for (int j = 1; j < 10; j++)
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
        ciphertext = _mm_aesenclast_si128(tmp1, KEY[10]);
        ciphertext = _mm_xor_si128(ciphertext, _mm_loadu_si128(&((__m128i *)ct)[i]));
        _mm_storeu_si128(&((__m128i *)pt)[i], ciphertext);
        ciphertext = _mm_shuffle_epi8(ciphertext, BSWAP_MASK);
        hash2 = _mm_xor_si128(hash2, ciphertext);
        gfmul(hash2, H, &hash2);
    }
    tmp1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)tweak), BSWAP_MASK);
    hash2 = _mm_xor_si128(hash2, tmp1);
    gfmul(hash2, H, &hash2);
    hash2 = _mm_xor_si128(hash2, lenswap);
    gfmul(hash2, H, &hash2);
    hash2 = _mm_shuffle_epi8(hash2, BSWAP_MASK);
    ciphertext = _mm_xor_si128(Z2, hash2);
    _mm_storeu_si128(&((__m128i *)pt)[0], ciphertext);
}
void HCTR_encrypt_8(const unsigned char *pt,
                  unsigned char *ct,
                  const unsigned char *tweak,
                  int pt_len,
                  ae_ctx *ctx)
{
    __m128i Z1 = _mm_loadu_si128((__m128i *)pt), Z2;
    __m128i D = _mm_setzero_si128(), hash2 = _mm_setzero_si128(), lenswap = _mm_setzero_si128();
    __m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
    __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
    __m128i EIGHT = _mm_set_epi32(0, 8, 0, 0);
    __m128i ctr1 = _mm_setzero_si128();
    __m128i ctr2, ctr3, ctr4, ctr5, ctr6, ctr7, ctr8;
    __m128i tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tweakswap, ciphertext, Z1Z2;
    __m128i H = _mm_loadu_si128((__m128i *)ctx->key2), H2, H3, H4, H5, H6, H7, H8;
    int i = 0;
    
    lenswap = _mm_insert_epi64(lenswap, pt_len * 8, 0);
    H = _mm_shuffle_epi8(H, BSWAP_MASK);
    gfmul1(H, H, &H2);
    gfmul1(H, H2, &H3);
    gfmul1(H, H3, &H4);
    gfmul1(H, H4, &H5);
    gfmul1(H, H5, &H6);
    gfmul1(H, H6, &H7);
    gfmul1(H, H7, &H8);
    H = multx(H);
    H2 = multx(H2);
    H3 = multx(H3);
    H4 = multx(H4);
    H5 = multx(H5);
    H6 = multx(H6);
    H7 = multx(H7);
    H8 = multx(H8);
    
    for (i = 0; i < (pt_len - 16) / 128; i++)
    {
        tmp1 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 1]), BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 2]), BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 3]), BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 4]), BSWAP_MASK);
        tmp5 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 5]), BSWAP_MASK);
        tmp6 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 6]), BSWAP_MASK);
        tmp7 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 7]), BSWAP_MASK);
        tmp8 = _mm_shuffle_epi8(_mm_loadu_si128(&((__m128i *)pt)[8 * i + 8]), BSWAP_MASK);
        tmp1 = _mm_xor_si128(D, tmp1);
        reduce8(H, H2, H3, H4, H5, H6, H7, H8, tmp8, tmp7, tmp6, tmp5, tmp4, tmp3, tmp2, tmp1, &D);
    }
    
    for (i = 8 * i + 1; i < pt_len / 16; i++)
    {
        tmp1 = _mm_load_si128(&((__m128i *)pt)[i]);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        D = _mm_xor_si128(D, tmp1);
        gfmul(D, H, &D);
    }
    tweakswap = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)tweak), BSWAP_MASK);
    D = _mm_xor_si128(D, tweakswap);
    gfmul(D, H, &D);
    D = _mm_xor_si128(D, lenswap);
    gfmul(D, H, &D);
    D = _mm_shuffle_epi8(D, BSWAP_MASK);
    Z1 = _mm_xor_si128(Z1, D);
    __m128i *KEY = (__m128i *)ctx->KEY;
    tmp1 = _mm_xor_si128(Z1, KEY[0]);
    
    for (i = 1; i < 10; i++)
        tmp1 = _mm_aesenc_si128(tmp1, KEY[i]);
    Z2 = _mm_aesenclast_si128(tmp1, KEY[10]);
    Z1Z2 = _mm_xor_si128(Z1, Z2);
    ctr1 = _mm_add_epi64(ctr1, ONE);
    ctr2 = _mm_add_epi64(ctr1, ONE);
    ctr3 = _mm_add_epi64(ctr2, ONE);
    ctr4 = _mm_add_epi64(ctr3, ONE);
    ctr5 = _mm_add_epi64(ctr4, ONE);
    ctr6 = _mm_add_epi64(ctr5, ONE);
    ctr7 = _mm_add_epi64(ctr6, ONE);
    ctr8 = _mm_add_epi64(ctr7, ONE);
    //printf("pt_len=%d\n",pt_len);
    for (i = 0; i < (pt_len - 16) / 128; i++)
    {
        //printf("i=%d\n",i);
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        tmp2 = _mm_shuffle_epi8(ctr2, BSWAP_EPI64);
        tmp3 = _mm_shuffle_epi8(ctr3, BSWAP_EPI64);
        tmp4 = _mm_shuffle_epi8(ctr4, BSWAP_EPI64);
        tmp5 = _mm_shuffle_epi8(ctr5, BSWAP_EPI64);
        tmp6 = _mm_shuffle_epi8(ctr6, BSWAP_EPI64);
        tmp7 = _mm_shuffle_epi8(ctr7, BSWAP_EPI64);
        tmp8 = _mm_shuffle_epi8(ctr8, BSWAP_EPI64);
        
        ctr1 = _mm_add_epi64(ctr1, EIGHT);
        ctr2 = _mm_add_epi64(ctr2, EIGHT);
        ctr3 = _mm_add_epi64(ctr3, EIGHT);
        ctr4 = _mm_add_epi64(ctr4, EIGHT);
        ctr5 = _mm_add_epi64(ctr5, EIGHT);
        ctr6 = _mm_add_epi64(ctr6, EIGHT);
        ctr7 = _mm_add_epi64(ctr7, EIGHT);
        ctr8 = _mm_add_epi64(ctr8, EIGHT);
        tmp1 = _mm_xor_si128(Z1Z2, tmp1);
        tmp2 = _mm_xor_si128(Z1Z2, tmp2);
        tmp3 = _mm_xor_si128(Z1Z2, tmp3);
        tmp4 = _mm_xor_si128(Z1Z2, tmp4);
        tmp5 = _mm_xor_si128(Z1Z2, tmp5);
        tmp6 = _mm_xor_si128(Z1Z2, tmp6);
        tmp7 = _mm_xor_si128(Z1Z2, tmp7);
        tmp8 = _mm_xor_si128(Z1Z2, tmp8);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp2 = _mm_xor_si128(tmp2, KEY[0]);
        tmp3 = _mm_xor_si128(tmp3, KEY[0]);
        tmp4 = _mm_xor_si128(tmp4, KEY[0]);
        tmp5 = _mm_xor_si128(tmp5, KEY[0]);
        tmp6 = _mm_xor_si128(tmp6, KEY[0]);
        tmp7 = _mm_xor_si128(tmp7, KEY[0]);
        tmp8 = _mm_xor_si128(tmp8, KEY[0]);
        
        for (int j = 1; j < 10 - 1; j += 2)
        {
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j]);
            tmp3 = _mm_aesenc_si128(tmp3, KEY[j]);
            tmp4 = _mm_aesenc_si128(tmp4, KEY[j]);
            tmp5 = _mm_aesenc_si128(tmp5, KEY[j]);
            tmp6 = _mm_aesenc_si128(tmp6, KEY[j]);
            tmp7 = _mm_aesenc_si128(tmp7, KEY[j]);
            tmp8 = _mm_aesenc_si128(tmp8, KEY[j]);
            tmp1 = _mm_aesenc_si128(tmp1, KEY[j + 1]);
            tmp2 = _mm_aesenc_si128(tmp2, KEY[j + 1]);
            tmp3 = _mm_aesenc_si128(tmp3, KEY[j + 1]);
            tmp4 = _mm_aesenc_si128(tmp4, KEY[j + 1]);
            tmp5 = _mm_aesenc_si128(tmp5, KEY[j + 1]);
            tmp6 = _mm_aesenc_si128(tmp6, KEY[j + 1]);
            tmp7 = _mm_aesenc_si128(tmp7, KEY[j + 1]);
            tmp8 = _mm_aesenc_si128(tmp8, KEY[j + 1]);
        }
        
        tmp1 = _mm_aesenc_si128(tmp1, KEY[10 - 1]);
        tmp2 = _mm_aesenc_si128(tmp2, KEY[10 - 1]);
        tmp3 = _mm_aesenc_si128(tmp3, KEY[10 - 1]);
        tmp4 = _mm_aesenc_si128(tmp4, KEY[10 - 1]);
        tmp5 = _mm_aesenc_si128(tmp5, KEY[10 - 1]);
        tmp6 = _mm_aesenc_si128(tmp6, KEY[10 - 1]);
        tmp7 = _mm_aesenc_si128(tmp7, KEY[10 - 1]);
        tmp8 = _mm_aesenc_si128(tmp8, KEY[10 - 1]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp2 = _mm_aesenclast_si128(tmp2, KEY[10]);
        tmp3 = _mm_aesenclast_si128(tmp3, KEY[10]);
        tmp4 = _mm_aesenclast_si128(tmp4, KEY[10]);
        tmp5 = _mm_aesenclast_si128(tmp5, KEY[10]);
        tmp6 = _mm_aesenclast_si128(tmp6, KEY[10]);
        tmp7 = _mm_aesenclast_si128(tmp7, KEY[10]);
        tmp8 = _mm_aesenclast_si128(tmp8, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i * 8 + 1]));
        tmp2 = _mm_xor_si128(tmp2, _mm_load_si128(&((__m128i *)pt)[i * 8 + 2]));
        tmp3 = _mm_xor_si128(tmp3, _mm_load_si128(&((__m128i *)pt)[i * 8 + 3]));
        tmp4 = _mm_xor_si128(tmp4, _mm_load_si128(&((__m128i *)pt)[i * 8 + 4]));
        tmp5 = _mm_xor_si128(tmp5, _mm_load_si128(&((__m128i *)pt)[i * 8 + 5]));
        tmp6 = _mm_xor_si128(tmp6, _mm_load_si128(&((__m128i *)pt)[i * 8 + 6]));
        tmp7 = _mm_xor_si128(tmp7, _mm_load_si128(&((__m128i *)pt)[i * 8 + 7]));
        tmp8 = _mm_xor_si128(tmp8, _mm_load_si128(&((__m128i *)pt)[i * 8 + 8]));
        //printf("%d\n",i*8+1);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 1], tmp1);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 2], tmp2);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 3], tmp3);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 4], tmp4);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 5], tmp5);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 6], tmp6);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 7], tmp7);
        _mm_store_si128(&((__m128i *)ct)[i * 8 + 8], tmp8);
        //printf("hello\n");
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_MASK);
        tmp3 = _mm_shuffle_epi8(tmp3, BSWAP_MASK);
        tmp4 = _mm_shuffle_epi8(tmp4, BSWAP_MASK);
        tmp5 = _mm_shuffle_epi8(tmp5, BSWAP_MASK);
        tmp6 = _mm_shuffle_epi8(tmp6, BSWAP_MASK);
        tmp7 = _mm_shuffle_epi8(tmp7, BSWAP_MASK);
        tmp8 = _mm_shuffle_epi8(tmp8, BSWAP_MASK);
        tmp1 = _mm_xor_si128(hash2, tmp1);
        reduce8(H, H2, H3, H4, H5, H6, H7, H8, tmp8, tmp7, tmp6, tmp5, tmp4, tmp3, tmp2, tmp1, &hash2);
    }
    for (i = 8 * i + 1; i < pt_len / 16; i++)
    {
        tmp1 = _mm_shuffle_epi8(ctr1, BSWAP_EPI64);
        ctr1 = _mm_add_epi64(ctr1, ONE);
        tmp1 = _mm_xor_si128(Z1Z2, tmp1);
        tmp1 = _mm_xor_si128(tmp1, KEY[0]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[1]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[2]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[3]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[4]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[5]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[6]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[7]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[8]);
        tmp1 = _mm_aesenc_si128(tmp1, KEY[9]);
        tmp1 = _mm_aesenclast_si128(tmp1, KEY[10]);
        tmp1 = _mm_xor_si128(tmp1, _mm_load_si128(&((__m128i *)pt)[i]));
        _mm_store_si128(&((__m128i *)ct)[i], tmp1);
        tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_MASK);
        hash2 = _mm_xor_si128(hash2, tmp1);
        gfmul(hash2, H, &hash2);
    }
    hash2 = _mm_xor_si128(hash2, tweakswap);
    gfmul(hash2, H, &hash2);
    hash2 = _mm_xor_si128(hash2, lenswap);
    gfmul(hash2, H, &hash2);
    hash2 = _mm_shuffle_epi8(hash2, BSWAP_MASK);
    ciphertext = _mm_xor_si128(Z2, hash2);
    _mm_storeu_si128(&((__m128i *)ct)[0], ciphertext);
}
#define USE_MM_MALLOC ((__SSE2__ || _M_IX86_FP >= 2) && !(_M_X64 || __x86_64__))
#define USE_POSIX_MEMALIGN (__ALTIVEC__ && __GLIBC__ && !__PPC64__)

ae_ctx *ae_allocate(void *misc)
{
    void *p;
    (void)misc; /* misc unused in this implementation */
#if USE_MM_MALLOC
    p = _mm_malloc(sizeof(ae_ctx), 16);
#elif USE_POSIX_MEMALIGN
    if (posix_memalign(&p, 16, sizeof(ae_ctx)) != 0)
        p = NULL;
#else
    p = malloc(sizeof(ae_ctx));
#endif
    return (ae_ctx *)p;
}

void ae_free(ae_ctx *ctx)
{
#if USE_MM_MALLOC
    _mm_free(ctx);
#else
    free(ctx);
#endif
}

/*int ae_encrypt(ae_ctx *ctx,
               const u8 *nonce,
               const u8 *pt,
               int pt_len,
               u8 *ct)
{
    HCTR_encrypt(pt, ct, nonce, pt_len, ctx);
    return pt_len;
    //尝试压缩
    int maxCompressedSize = LZ4_compressBound(pt_len);
    unsigned char* compressedData = new unsigned char[maxCompressedSize];
    // 压缩数据
    int outputLen = LZ4_compress_default(
        reinterpret_cast<const char*>(pt),
        reinterpret_cast<char*>(compressedData),
        pt_len,
        maxCompressedSize);
    output2(pt,pt_len);
    cout<<"outputLen = "<<outputLen<<endl;
    int space = pt_len-outputLen;
    cout<<"space = "<<space<<endl;
    if(space<24){
        HCTR_encrypt(pt, ct, nonce, pt_len, ctx);
        iszip = 0; // no zip
    }
    delete[] compressedData;
    return pt_len;
    
}*/

