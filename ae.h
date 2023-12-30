// AE template from OCB code https://www.cs.ucdavis.edu/~rogaway/ocb/performance/
#ifndef _AE_H_
#define _AE_H_
typedef unsigned char u8;
typedef struct _ae_ctx ae_ctx;

#define ALIGN(n) __attribute__((aligned(n)))

ae_ctx *ae_allocate(void *misc);
void ae_free(ae_ctx *ctx);

struct _ae_ctx
{
    ALIGN(16) u8 key2[16];
    ALIGN(16) u8 KEY[16 * 15];
    ALIGN(16) u8 KEY2[16 * 15];
};

int ae_init(ae_ctx *ctx,
            const u8 *key,
            int key_len,
            int nonce_len,
            int tag_len);

int ae_encrypt(ae_ctx *ctx,
               const u8 *nonce,
               const u8 *pt,
               int pt_len,
               u8 *ct,
               int *iszip);

int ae_decrypt(ae_ctx *ctx,
               const u8 *nonce,
               const u8 *ct,
               int ct_len,
               u8 *pt,
               int iszip,
               int zip_len);
#endif