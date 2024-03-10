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
    u8 key[32];
    u8 pt[4096] = {0};
    u8 pt2[4096] = {0};
    u8 ct[4096] = {0};
    ae_ctx *ctx = ae_allocate(NULL);
    ALIGN(16) u8 tweak[16];
    for (int i = 0; i < 16; i++)
        tweak[i] = 0;
    for (int i = 0; i < 32; i++)
        key[i] = i;
    for (int i = 0; i < 4096; i++)
        pt[i] = i;
    ae_init(ctx, key, 32, 0, 0);
    //char partname[30];
    //sprintf(partname, "./part/part_1456");
   // FILE *fin=fopen(partname,"rb");
    //int ret=fread(pt, 1, 4096, fin);
    int pt_len=4096;
    //printf("pt:\n");
    //output(pt,pt_len);
    int iszip=-1;
    ae_encrypt(ctx, tweak, pt, pt_len, ct,&iszip);
    printf("iszip = %d\n",iszip);
    //printf("ct:\n");
    //output(ct,pt_len);
    ae_decrypt(ctx, tweak, ct, pt_len, pt2,iszip);
    //printf("pt2:\n");
    //output(pt2,pt_len);
    int sign=0;
    for(int i=0;i<pt_len;i++) if(pt2[i]!=pt[i]) sign=1;
    if(sign==0) printf("YES!\n");
    else printf("NO!\n");
    ae_free(ctx);
    return 0;
}