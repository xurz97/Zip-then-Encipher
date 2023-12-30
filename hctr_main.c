#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"
 //linux
// #include <intrin.h>  //windows
#include "ae.h"
#include <stdlib.h>

#define ALIGN(n) __attribute__((aligned(n)))

// linux
void output(unsigned char *arr, int num)
{
    for (int i = 0; i < num; i++)
    {
        printf("%02x", arr[i]);
        if (i % 16 == 15)
            printf("\n");
    }
}
int main(int argc, char **argv)
{
    ALIGN(16) u8 key[32];
    ALIGN(16) u8 pt[4096] = {0};
    ALIGN(16) u8 pt2[4096] = {0};
    ALIGN(16) u8 ct[4096] = {0};
    ae_ctx *ctx = ae_allocate(NULL);
    ALIGN(16) u8 tweak[16];
    for (int i = 0; i < 16; i++)
        tweak[i] = 0;
    for (int i = 0; i < 32; i++)
        key[i] = i;
    for (int i = 0; i < 4096; i++)
        pt[i] = i;
    ae_init(ctx, key, 32, 0, 0);
    int pt_len=1024;
    output(pt,pt_len);
    int iszip=-1;
    int zip_len=ae_encrypt(ctx, tweak, pt, pt_len, ct,&iszip);
    printf("iszip = %d\n",iszip);
    output(ct,pt_len);
    ae_decrypt(ctx, tweak, ct, pt_len, pt2,iszip,zip_len);
    output(pt2,pt_len);
    ae_free(ctx);
    return 0;
}