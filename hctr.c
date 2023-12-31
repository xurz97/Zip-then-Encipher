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
    u8 compressedData[4096];
    // 压缩数据
    int outputLen = LZ4_compress_default(
        (const char*)(pt),
        (char*)(compressedData),
        pt_len,
        maxCompressedSize);
    //printf("outputLen = %d\n",outputLen);
    int space = pt_len-outputLen;
    //printf("space = %d\n",space);
    if(space<24){
        HCTR_encrypt(pt, ct, nonce, pt_len, ctx);
        *iszip = 0; // no zip
        return pt_len;
    }
    ((uint64_t*)ct)[0]=123;
    u8 tempNonce[16];
    ((uint64_t*)tempNonce)[0]=((uint64_t*)nonce)[0];
    ((uint64_t*)tempNonce)[1]=((uint64_t*)ct)[0];
    for(int i=outputLen;i<pt_len-8;i++) compressedData[i]=0;
    //output2(compressedData,pt_len-8);
    HCTR_encrypt(compressedData, ct+8, tempNonce, pt_len-8, ctx);
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
    HCTR_decrypt(ct+8, compressedData, tempNonce, ct_len-8, ctx);
    if(ischeck(compressedData,zip_len,ct_len-8)) return -1;//验证失败
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

