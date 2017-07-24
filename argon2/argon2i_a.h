#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "blake2/blake2b.h"
#include "argon2i.h"

#define ARGON2_SYNC_POINTS 4
#define ARGON2I_BLOCK_SIZE 1024
#define ARGON2I_QWORDS_IN_BLOCK ARGON2I_BLOCK_SIZE/8


typedef struct MemCo
{
    size_t i;
    size_t j;
}MemCo;

typedef uint64_t Block[ARGON2I_QWORDS_IN_BLOCK];


static inline void Hp1024toX(const uint64_t in[], uint8_t out[], size_t tau)
{
    uint32_t inp[257];
    inp[0] = tau;
    memcpy(inp+1,in,1024);
    if(tau <= 64)
    {
        blake2b1028toX(inp,out,tau);
    }
    else
    {
        size_t r = (tau%32 == 0)?tau/32-2:tau/32-1;
        SuperLong V[r];
        blake2b1028to64(inp,V[0]);
        memcpy(out,V[0],32);
        for(size_t i = 1; i < r; i++)
        {
            blake2b64to64(V[i-1],V[i]);
            memcpy(out+i*4,V[i],32);
        }
        blake2b64toX(V[r-1],out+r*ARGON2I_QWORDS_IN_SUPER_LONG,tau-32*r);
    }
}

static inline void Hp72to1024(const uint64_t in[], uint64_t out[])
{
    SuperLong V[30];
    uint32_t inp[19];
    inp[0] = 1024;
    memcpy(inp+1,in,72);
    blake2b76to64(inp,V[0]);
    memcpy(out,V[0],32);
    for(size_t i = 1; i < 30; i++)
    {
        blake2b64to64(V[i-1],V[i]);
        memcpy(out+i*4,V[i],32);
    }
    blake2b64to64(V[29],out+120);
}

static inline void R(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d)
{
    *a = *a+*b+2*((uint32_t)*a)*((uint32_t)*b);
    *d^= *a;
    *d = *d<<32|*d>>32;
    *c = *c+*d+2*((uint32_t)*c)*((uint32_t)*d);
    *b^= *c;
    *b = *b<<40|*b>>24;
    *a = *a+*b+2*((uint32_t)*a)*((uint32_t)*b);
    *d^= *a;
    *d = *d<<48|*d>>16;
    *c = *c+*d+2*((uint32_t)*c)*((uint32_t)*d);
    *b^= *c;
    *b = *b<<1|*b>>63;
}

static inline void P(uint64_t* v0, uint64_t* v1, uint64_t* v2, uint64_t* v3, uint64_t* v4, uint64_t* v5, uint64_t* v6, uint64_t* v7, uint64_t* v8, uint64_t* v9, uint64_t* v10, uint64_t* v11, uint64_t* v12, uint64_t* v13, uint64_t* v14, uint64_t* v15)
{
    R(v0,v4,v8,v12);
    R(v1,v5,v9,v13);
    R(v2,v6,v10,v14);
    R(v3,v7,v11,v15);
    R(v0,v5,v10,v15);
    R(v1,v6,v11,v12);
    R(v2,v7,v8,v13);
    R(v3,v4,v9,v14);
}

static inline void blockXor(Block z, Block x, Block y)
{
    for(size_t i = 0; i < ARGON2I_QWORDS_IN_BLOCK; i++)
    {
        z[i] = x[i]^y[i];
    }
}

static inline void Gi(Block z, Block x, Block y)
{
    Block r;
    blockXor(r,x,y);
    memcpy(z,r,ARGON2I_BLOCK_SIZE);
    P(r,r+1,r+2,r+3,r+4,r+5,r+6,r+7,r+8,r+9,r+10,r+11,r+12,r+13,r+14,r+15);
    P(r+16,r+17,r+18,r+19,r+20,r+21,r+22,r+23,r+24,r+25,r+26,r+27,r+28,r+29,r+30,r+31);
    P(r+32,r+33,r+34,r+35,r+36,r+37,r+38,r+39,r+40,r+41,r+42,r+43,r+44,r+45,r+46,r+47);
    P(r+48,r+49,r+50,r+51,r+52,r+53,r+54,r+55,r+56,r+57,r+58,r+59,r+60,r+61,r+62,r+63);
    P(r+64,r+65,r+66,r+67,r+68,r+69,r+70,r+71,r+72,r+73,r+74,r+75,r+76,r+77,r+78,r+79);
    P(r+80,r+81,r+82,r+83,r+84,r+85,r+86,r+87,r+88,r+89,r+90,r+91,r+92,r+93,r+94,r+95);
    P(r+96,r+97,r+98,r+99,r+100,r+101,r+102,r+103,r+104,r+105,r+106,r+107,r+108,r+109,r+110,r+111);
    P(r+112,r+113,r+114,r+115,r+116,r+117,r+118,r+119,r+120,r+121,r+122,r+123,r+124,r+125,r+126,r+127);
    P(r,r+8,r+16,r+24,r+32,r+40,r+48,r+56,r+64,r+72,r+80,r+88,r+96,r+104,r+112,r+120);
    P(r+1,r+9,r+17,r+25,r+33,r+41,r+49,r+57,r+65,r+73,r+81,r+89,r+97,r+105,r+113,r+121);
    P(r+2,r+10,r+18,r+26,r+34,r+42,r+50,r+58,r+66,r+74,r+82,r+90,r+98,r+106,r+114,r+122);
    P(r+3,r+11,r+19,r+27,r+35,r+43,r+51,r+59,r+67,r+75,r+83,r+91,r+99,r+107,r+115,r+123);
    P(r+4,r+12,r+20,r+28,r+36,r+44,r+52,r+60,r+68,r+76,r+84,r+92,r+100,r+108,r+116,r+124);
    P(r+5,r+13,r+21,r+29,r+37,r+45,r+53,r+61,r+69,r+77,r+85,r+93,r+101,r+109,r+117,r+125);
    P(r+6,r+14,r+22,r+30,r+38,r+46,r+54,r+62,r+70,r+78,r+86,r+94,r+102,r+110,r+118,r+126);
    P(r+7,r+15,r+23,r+31,r+39,r+47,r+55,r+63,r+71,r+79,r+87,r+95,r+103,r+111,r+119,r+127);
    blockXor(z,z,r);
}

static inline void G0(Block r, Block x)
{
    memcpy(r,x,ARGON2I_BLOCK_SIZE);
    P(r,r+1,r+2,r+3,r+4,r+5,r+6,r+7,r+8,r+9,r+10,r+11,r+12,r+13,r+14,r+15);
    P(r+16,r+17,r+18,r+19,r+20,r+21,r+22,r+23,r+24,r+25,r+26,r+27,r+28,r+29,r+30,r+31);
    P(r+32,r+33,r+34,r+35,r+36,r+37,r+38,r+39,r+40,r+41,r+42,r+43,r+44,r+45,r+46,r+47);
    P(r+48,r+49,r+50,r+51,r+52,r+53,r+54,r+55,r+56,r+57,r+58,r+59,r+60,r+61,r+62,r+63);
    P(r+64,r+65,r+66,r+67,r+68,r+69,r+70,r+71,r+72,r+73,r+74,r+75,r+76,r+77,r+78,r+79);
    P(r+80,r+81,r+82,r+83,r+84,r+85,r+86,r+87,r+88,r+89,r+90,r+91,r+92,r+93,r+94,r+95);
    P(r+96,r+97,r+98,r+99,r+100,r+101,r+102,r+103,r+104,r+105,r+106,r+107,r+108,r+109,r+110,r+111);
    P(r+112,r+113,r+114,r+115,r+116,r+117,r+118,r+119,r+120,r+121,r+122,r+123,r+124,r+125,r+126,r+127);
    P(r,r+8,r+16,r+24,r+32,r+40,r+48,r+56,r+64,r+72,r+80,r+88,r+96,r+104,r+112,r+120);
    P(r+1,r+9,r+17,r+25,r+33,r+41,r+49,r+57,r+65,r+73,r+81,r+89,r+97,r+105,r+113,r+121);
    P(r+2,r+10,r+18,r+26,r+34,r+42,r+50,r+58,r+66,r+74,r+82,r+90,r+98,r+106,r+114,r+122);
    P(r+3,r+11,r+19,r+27,r+35,r+43,r+51,r+59,r+67,r+75,r+83,r+91,r+99,r+107,r+115,r+123);
    P(r+4,r+12,r+20,r+28,r+36,r+44,r+52,r+60,r+68,r+76,r+84,r+92,r+100,r+108,r+116,r+124);
    P(r+5,r+13,r+21,r+29,r+37,r+45,r+53,r+61,r+69,r+77,r+85,r+93,r+101,r+109,r+117,r+125);
    P(r+6,r+14,r+22,r+30,r+38,r+46,r+54,r+62,r+70,r+78,r+86,r+94,r+102,r+110,r+118,r+126);
    P(r+7,r+15,r+23,r+31,r+39,r+47,r+55,r+63,r+71,r+79,r+87,r+95,r+103,r+111,r+119,r+127);
    blockXor(r,x,r);
}

static inline void Ge(Block z, Block x, Block y, Block w)
{
    Block r;
    blockXor(r,x,y);
    blockXor(z,w,r);
    P(r,r+1,r+2,r+3,r+4,r+5,r+6,r+7,r+8,r+9,r+10,r+11,r+12,r+13,r+14,r+15);
    P(r+16,r+17,r+18,r+19,r+20,r+21,r+22,r+23,r+24,r+25,r+26,r+27,r+28,r+29,r+30,r+31);
    P(r+32,r+33,r+34,r+35,r+36,r+37,r+38,r+39,r+40,r+41,r+42,r+43,r+44,r+45,r+46,r+47);
    P(r+48,r+49,r+50,r+51,r+52,r+53,r+54,r+55,r+56,r+57,r+58,r+59,r+60,r+61,r+62,r+63);
    P(r+64,r+65,r+66,r+67,r+68,r+69,r+70,r+71,r+72,r+73,r+74,r+75,r+76,r+77,r+78,r+79);
    P(r+80,r+81,r+82,r+83,r+84,r+85,r+86,r+87,r+88,r+89,r+90,r+91,r+92,r+93,r+94,r+95);
    P(r+96,r+97,r+98,r+99,r+100,r+101,r+102,r+103,r+104,r+105,r+106,r+107,r+108,r+109,r+110,r+111);
    P(r+112,r+113,r+114,r+115,r+116,r+117,r+118,r+119,r+120,r+121,r+122,r+123,r+124,r+125,r+126,r+127);
    P(r,r+8,r+16,r+24,r+32,r+40,r+48,r+56,r+64,r+72,r+80,r+88,r+96,r+104,r+112,r+120);
    P(r+1,r+9,r+17,r+25,r+33,r+41,r+49,r+57,r+65,r+73,r+81,r+89,r+97,r+105,r+113,r+121);
    P(r+2,r+10,r+18,r+26,r+34,r+42,r+50,r+58,r+66,r+74,r+82,r+90,r+98,r+106,r+114,r+122);
    P(r+3,r+11,r+19,r+27,r+35,r+43,r+51,r+59,r+67,r+75,r+83,r+91,r+99,r+107,r+115,r+123);
    P(r+4,r+12,r+20,r+28,r+36,r+44,r+52,r+60,r+68,r+76,r+84,r+92,r+100,r+108,r+116,r+124);
    P(r+5,r+13,r+21,r+29,r+37,r+45,r+53,r+61,r+69,r+77,r+85,r+93,r+101,r+109,r+117,r+125);
    P(r+6,r+14,r+22,r+30,r+38,r+46,r+54,r+62,r+70,r+78,r+86,r+94,r+102,r+110,r+118,r+126);
    P(r+7,r+15,r+23,r+31,r+39,r+47,r+55,r+63,r+71,r+79,r+87,r+95,r+103,r+111,r+119,r+127);
    blockXor(z,z,r);
}

static inline MemCo phi(size_t n, uint32_t r, size_t l, uint8_t s, size_t ll, size_t m1, size_t m3, size_t m4, size_t* index, Block adr)
{
    size_t card;
    MemCo ans;
    ans.i = (adr[*index]>>32)%ll;
    if(ans.i == l)
    {
        card = (r>1)?m4-2:n-1;
    }
    else
    {
        card = (r>1)?m3:m1*s;
        if(n%m1 == 0)
        {
            card--;
        }
    }
    ans.j = (uint32_t)adr[*index];
    ans.j*= ans.j;
    ans.j>>= 32;
    ans.j*= card;
    ans.j>>= 32;
    ans.j = card - 1 - ans.j;
    if(r>1)
    {
        if(ans.i == l)
        {
            ans.j+= n+1;
        }
        else
        {
            ans.j+= m1*(s+1);
        }
    }
    ans.j%= m4;
    (*index)++;
    return ans;
}

static inline size_t phi0(size_t n, size_t* index, Block adr)
{
    size_t card = n-1, j = (uint32_t)adr[*index];
    j*= j;
    j>>= 32;
    j*= card;
    j>>= 32;
    (*index)++;
    return card - 1 - j;
}

static inline void threadWait(pthread_mutex_t* waitMtx, pthread_cond_t* waitCnd, size_t* waitCnt, size_t waitCntInit)
{
    pthread_mutex_lock(waitMtx);
    if(*waitCnt)
    {
        (*waitCnt)--;
        pthread_cond_wait(waitCnd,waitMtx);
    }
    else
    {
        *waitCnt = waitCntInit;
        pthread_cond_broadcast(waitCnd);
    }
    pthread_mutex_unlock(waitMtx);
}
