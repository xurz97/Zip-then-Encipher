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
static u8 tweak[16];
int iszip=-1;
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
    unsigned long long clock1, clock2,tot=0;
    //double cpb[101];
    int pt_len = 4096;
    char partname[30];
    //FILE *fin=fopen("../part_1594","rb");
    //printf("%d\n",(fin==NULL));
    //return 0;
    double cpb=0;
    int ziptot=0;
    while (1)
    {
        ++cnt;
        sprintf(partname, "./part/part_%d", cnt);
        
        FILE *fin=fopen(partname,"rb");
        if(fin==NULL) break;
        int ret=fread(pt, 1, 4096, fin);
        int zip_len; //= ae_encrypt(ctx, tweak, pt, pt_len, ct, &iszip);
        //while (pt_len <= 4096)
        //{
            //for (int z = 0; z < 101; z++)
            //{
                // zip_len=ae_encrypt(ctx, tweak, pt, pt_len, ct,&iszip);

                clock1 = __rdtscp(&ui);
                //for (int j = 0; j < 1e4; j++)
                //{
            //printf("num=%d\n",cnt);
                    //printf("begin\n");
                    for(int z=0;z<100;z++)
                    zip_len = ae_encrypt(ctx, tweak, pt, pt_len, ct, &iszip);
                    //printf("end\n");
                    //printf("num=%d\n",cnt);
                    // ae_decrypt(ctx, tweak, ct, pt_len, pt2,iszip,zip_len);
                //}
                clock2 = __rdtscp(&ui);
                double cur = (clock2-clock1)/(1e2*4096);
                ziptot+=iszip;
                //printf("cnt=%d cur=%.2f\n",cnt,cur);
                //tot+=clock2-clock1;
                cpb+=cur;
                //cpb[z] = (clock2 - clock1) / (1e4 * pt_len);
            //}
            //qsort(cpb, 101, sizeof(double), compare);
            //printf("length = %d bytes , cpb = %.3f cycles/byte iszip = %d \n", pt_len, cpb[50], iszip);
            //pt_len += 128;
        //}
        //sprintf(partname, "../part_%d", ++num);
        fclose(fin);
        //printf("num=%d\n",cnt);
    }
    ae_free(ctx);
    printf("cpb = %f cycles/byte\n",cpb/cnt);
    printf("num= %d\n",cnt);
    printf("iszip= %d\n",ziptot);
    return 0;
}