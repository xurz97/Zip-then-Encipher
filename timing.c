// gcc lz4.c hctr.c timing.c -march=native -O2


#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"
// linux
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
static unsigned int cnt = 0;
static unsigned int ui;
static u8 key[32];
static u8 pt[8192] = {0};
static u8 ct[8192] = {0};
static u8 pt2[8192] = {0};
static u8 tweak[16];

int main(int argc, char **argv)
{
    ae_ctx *ctx = ae_allocate(NULL);
    for (int i = 0; i < 16; i++)
        tweak[i] = 0;
    for (int i = 0; i < 32; i++)
        key[i] = i;
    for (int i = 0; i < 4096; i++)
        pt[i] = i;
    ae_init(ctx, key, 32, 0, 0);
    unsigned long long clock1, clock2;
    int pt_len = 4096;
    char partname[30];
    double cpb=0;
    int ziptot=0;
    cnt=0;
    int iszip=-1;
    while (1)
    {
        ++cnt;
        sprintf(partname, "./part/part_%d", cnt);
        
        FILE *fin=fopen(partname,"rb");
        if(fin==NULL) break;
        int ret=fread(pt, 1, 4096, fin);
        int zip_len; //= ae_encrypt(ctx, tweak, pt, pt_len, ct, &iszip);
        clock1 = __rdtscp(&ui);
        for(int z=0;z<100;z++)
            ae_encrypt(ctx, tweak, pt, pt_len, ct, &iszip);
        clock2 = __rdtscp(&ui);
        double cur = (clock2-clock1)/(1e2*4096);
        ziptot+=iszip;
        cpb+=cur;
        fclose(fin);
    }
    //ae_free(ctx);
    cnt--;
    printf("encrypt cpb = %f cycles/byte\n",cpb/cnt);
    printf("slice number = %d\n",cnt);
    printf("zip slice number = %d\n",ziptot);
    cnt=0;
    cpb=0;
        while (1)
    {
        ++cnt;
        sprintf(partname, "./part/part_%d", cnt);
        
        FILE *fin=fopen(partname,"rb");
        if(fin==NULL) break;
        int ret=fread(pt, 1, 4096, fin);
        ae_encrypt(ctx, tweak, pt, pt_len, ct, &iszip);
        clock1 = __rdtscp(&ui);
        //printf("cnt = %d\n",cnt);
        for(int z=0;z<100;z++)
            ae_decrypt(ctx, tweak, ct, pt_len, pt2, iszip);
        clock2 = __rdtscp(&ui);
        double cur = (clock2-clock1)/(1e2*4096);
        ziptot+=iszip;
        cpb+=cur;
        fclose(fin);
    }
    cnt--;
    printf("decrypt cpb = %f cycles/byte\n",cpb/cnt);
    ae_free(ctx);
    return 0;
}