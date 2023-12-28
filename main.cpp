#include <cstdio>
#include "aes.h"
using namespace std;
void output(unsigned char *arr, int num)
{
    for (int i = 0; i < num; i++)
    {
        printf("%02x", arr[i]);
        if (i % 16 == 15)
            printf("\n");
    }
}
int main() {
    AES_KEY ekey,dkey;
    u8 userKey[16];
    u8 pt[16],ct[16];
    for(int i=0;i<16;i++) userKey[i]=pt[i]=i;
    AES_set_encrypt_key(userKey,128,&ekey);
    AES_NI_set_decrypt_key(dkey.rd_key,ekey.rd_key);
    AES_encrypt(pt,ct,&ekey);
    output(pt,16);
    output(ct,16);
    AES_decrypt(ct,pt,&dkey);
    output(ct,16);
    output(pt,16);
    return 0;
}