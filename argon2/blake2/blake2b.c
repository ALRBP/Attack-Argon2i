#include <string.h>
#include "blake2b.h"


const uint64_t IV[8] =
{
    UINT64_C(0x6a09e667f3bcc908),
    UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b),
    UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1),
    UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b),
    UINT64_C(0x5be0cd19137e2179)
};
const unsigned int blake2bSigma[12][16] =
{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};


static inline void G(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d, size_t r, size_t i, uint64_t m[])
{
    *a = *a+*b+m[blake2bSigma[r][2*i]];
    *d^= *a;
    *d = *d<<32|*d>>32;
    *c = *c+*d;
    *b^= *c;
    *b = *b<<40|*b>>24;
    *a = *a+*b+m[blake2bSigma[r][2*i+1]];
    *d^= *a;
    *d = *d<<48|*d>>16;
    *c = *c+*d;
    *b^= *c;
    *b = *b<<1|*b>>63;
}

static inline void R(uint64_t v[], size_t r, uint64_t m[])
{
    G(v+0,v+4,v+8,v+12,r,0,m);
    G(v+1,v+5,v+9,v+13,r,1,m);
    G(v+2,v+6,v+10,v+14,r,2,m);
    G(v+3,v+7,v+11,v+15,r,3,m);
    G(v+0,v+5,v+10,v+15,r,4,m);
    G(v+1,v+6,v+11,v+12,r,5,m);
    G(v+2,v+7,v+8,v+13,r,6,m);
    G(v+3,v+4,v+9,v+14,r,7,m);
}

static inline void blake2bCompress(uint64_t h[], uint64_t m[], uint64_t t, uint64_t f)
{
    uint64_t v[16];
    v[0] = h[0];
    v[1] = h[1];
    v[2] = h[2];
    v[3] = h[3];
    v[4] = h[4];
    v[5] = h[5];
    v[6] = h[6];
    v[7] = h[7];
    v[8] = IV[0];
    v[9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = IV[4]^t;
    v[13] = IV[5];
    v[14] = IV[6]^f;
    v[15] = IV[7]^f;
    R(v,0,m);
    R(v,1,m);
    R(v,2,m);
    R(v,3,m);
    R(v,4,m);
    R(v,5,m);
    R(v,6,m);
    R(v,7,m);
    R(v,8,m);
    R(v,9,m);
    R(v,10,m);
    R(v,11,m);
    h[0]^= v[0]^v[8];
    h[1]^= v[1]^v[9];
    h[2]^= v[2]^v[10];
    h[3]^= v[3]^v[11];
    h[4]^= v[4]^v[12];
    h[5]^= v[5]^v[13];
    h[6]^= v[6]^v[14];
    h[7]^= v[7]^v[15];
}


void blake2b64to64(const uint64_t in[], uint64_t out[])
{
    uint64_t P = 0x1010040;
    uint64_t m[16];
    memcpy(m,in,64);
    memset(m+8,0,64);
    out[0] = IV[0]^P;
    out[1] = IV[1];
    out[2] = IV[2];
    out[3] = IV[3];
    out[4] = IV[4];
    out[5] = IV[5];
    out[6] = IV[6];
    out[7] = IV[7];
    blake2bCompress(out,m,64,0xffffffffffffffff);
}
 
void blake2b64toX(const uint64_t in[], uint8_t out[], size_t x)
{
    uint64_t P = x+0x1010000;
    uint64_t m[16];
    memcpy(m,in,64);
    memset(m+8,0,64);
    uint64_t h[8];
    h[0] = IV[0]^P;
    h[1] = IV[1];
    h[2] = IV[2];
    h[3] = IV[3];
    h[4] = IV[4];
    h[5] = IV[5];
    h[6] = IV[6];
    h[7] = IV[7];
    blake2bCompress(h,m,64,0xffffffffffffffff);
    memcpy(out,h,x);
}
 
void blake2b76to64(const uint32_t in[], uint64_t out[])
{
    uint64_t P = 0x1010040;
    uint64_t m[16];
    memset(m+9,0,56);
    memcpy(m,in,76);
    out[0] = IV[0]^P;
    out[1] = IV[1];
    out[2] = IV[2];
    out[3] = IV[3];
    out[4] = IV[4];
    out[5] = IV[5];
    out[6] = IV[6];
    out[7] = IV[7];
    blake2bCompress(out,m,76,0xffffffffffffffff);
}
 
void blake2b1028to64(const uint32_t in[], uint64_t out[])
{
    uint64_t P = 0x1010040;
    uint64_t m[144];
    memset(m+128,0,128);
    memcpy(m,in,1028);
    out[0] = IV[0]^P;
    out[1] = IV[1];
    out[2] = IV[2];
    out[3] = IV[3];
    out[4] = IV[4];
    out[5] = IV[5];
    out[6] = IV[6];
    out[7] = IV[7];
    blake2bCompress(out,m,128,0);
    blake2bCompress(out,m+16,256,0);
    blake2bCompress(out,m+32,384,0);
    blake2bCompress(out,m+48,512,0);
    blake2bCompress(out,m+64,640,0);
    blake2bCompress(out,m+80,768,0);
    blake2bCompress(out,m+96,896,0);
    blake2bCompress(out,m+112,1024,0);
    blake2bCompress(out,m+128,1028,0xffffffffffffffff);
}
 
void blake2b1028toX(const uint32_t in[], uint8_t out[], size_t x)
{
    uint64_t P = x+0x1010000;
    uint64_t m[144];
    memset(m+128,0,128);
    memcpy(m,in,1028);
    uint64_t h[8];
    h[0] = IV[0]^P;
    h[1] = IV[1];
    h[2] = IV[2];
    h[3] = IV[3];
    h[4] = IV[4];
    h[5] = IV[5];
    h[6] = IV[6];
    h[7] = IV[7];
    blake2bCompress(h,m,128,0);
    blake2bCompress(h,m+16,256,0);
    blake2bCompress(h,m+32,384,0);
    blake2bCompress(h,m+48,512,0);
    blake2bCompress(h,m+64,640,0);
    blake2bCompress(h,m+80,768,0);
    blake2bCompress(h,m+96,896,0);
    blake2bCompress(h,m+112,1024,0);
    blake2bCompress(h,m+128,1028,0xffffffffffffffff);
    memcpy(out,h,x);
}
 
void blake2bXto64(const uint8_t in[], uint64_t out[], size_t x)
{
    size_t it = (x%128 == 0)?x/128:x/128+1;
    size_t ml = it*16;
    size_t lf = (x/128)*16;
    uint64_t P = 0x1010040;
    uint64_t m[ml];
    memset(m+lf,0,(ml-lf)*8);
    memcpy(m,in,x);
    out[0] = IV[0]^P;
    out[1] = IV[1];
    out[2] = IV[2];
    out[3] = IV[3];
    out[4] = IV[4];
    out[5] = IV[5];
    out[6] = IV[6];
    out[7] = IV[7];
    for(size_t i = 1; i < it; i++)
    {
        blake2bCompress(out,m+(16*(i-1)),128*i,0);
    }
    blake2bCompress(out,m,x,0xffffffffffffffff);
}
