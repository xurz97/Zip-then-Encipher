#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"
 //linux
// #include <intrin.h>  //windows
#include "ae.h"
#include <stdlib.h>
#include <x86intrin.h>

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

int compare(const void *a, const void *b)
{
    double ret = *(double *)a - *(double *)b;
    if (ret > 0)
    {
        return 1;
    }
    else if (ret < 0)
    {
        return -1;
    }
    else
        return 0;
}

int main(int argc, char **argv)
{
    unsigned int ui;
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
    unsigned long long clock1, clock2;
    double cpb[101];
    int pt_len=128;
    /*printf("pt:\n");
    output(pt,pt_len);
    int iszip=-1;
    int zip_len=ae_encrypt(ctx, tweak, pt, pt_len, ct,&iszip);
    printf("iszip = %d\n",iszip);
    printf("ct:\n");
    output(ct,pt_len);
    ae_decrypt(ctx, tweak, ct, pt_len, pt2,iszip,zip_len);
    printf("pt2:\n");
    output(pt2,pt_len);
    int sign=0;
    for(int i=0;i<pt_len;i++) if(pt2[i]!=pt[i]) sign=1;
    if(sign==0) printf("YES!\n");
    else printf("NO!\n");*/
    int iszip=-1;
    int zip_len=ae_encrypt(ctx, tweak, pt, pt_len, ct,&iszip);
    while(pt_len<=4096){
    for (int z = 0; z < 101; z++)
    {
        zip_len=ae_encrypt(ctx, tweak, pt, pt_len, ct,&iszip);
        clock1 = __rdtscp(&ui);
        for (int j = 0; j < 1e4; j++)
        {
            //zip_len=ae_encrypt(ctx, tweak, pt, pt_len, ct,&iszip);
            ae_decrypt(ctx, tweak, ct, pt_len, pt2,iszip,zip_len);
        }
        clock2 = __rdtscp(&ui);
        cpb[z] = (clock2 - clock1) / (1e4 * pt_len);
    }
    qsort(cpb, 101, sizeof(double), compare);
    printf("length = %d bytes , cpb = %.3f cycles/byte iszip = %d \n", pt_len, cpb[50],iszip);
    pt_len+=128;
    }ae_free(ctx);
    return 0;
}