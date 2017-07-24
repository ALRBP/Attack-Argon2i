#include <stdlib.h>
#include "argon2i_a.h"


typedef struct Argon2iSharedVars
{
    size_t ll;
    uint32_t tr;
    size_t m1;
    size_t m2;
    size_t m3;
    size_t m4;
    size_t q;
    SuperLong H0;
    Block** B;
    size_t waitCnt;
    size_t waitCntInit;
    pthread_mutex_t waitMtx;
    pthread_cond_t waitCnd;
}Argon2iSharedVars;

typedef struct Argon2iThreadParam
{
    Argon2iSharedVars* vars;
    size_t in;
}Argon2iThreadParam;


void *argon2iThreadF(void* prm);


static inline void G(Block z, Block x, Block y)
{
    Block r;
    blockXor(r,x,y);
    blockXor(z,z,r);
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


void argon2i(size_t p, size_t mem, uint32_t iters, const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, void* out, size_t outlen)
{
    Argon2iSharedVars vars;
    vars.ll = p;
    vars.tr = iters;
    vars.q = mem;
    vars.m1 = mem/(ARGON2_SYNC_POINTS*p);
    vars.m2 = vars.m1*2;
    vars.m3 = vars.m1*3;
    vars.m4 = vars.m1*4;
    size_t t1 = 28+pwdlen;
    size_t t2 = 32+pwdlen+saltlen;
    uint8_t init[t2+8];
    pthread_mutex_init(&(vars.waitMtx),NULL);
    pthread_cond_init(&(vars.waitCnd),NULL);
    vars.B = (Block**)malloc(p*sizeof(Block*));
    for(size_t i = 0; i < p; i++)
    {
        vars.B[i] = (Block*)malloc(vars.m4*sizeof(Block));
    }
    memcpy(init,&p,4);
    memcpy(init+4,&outlen,4);
    memcpy(init+8,&mem,4);
    memcpy(init+12,&iters,4);
    memset(init+16,0x13,1);
    memset(init+17,0,3);
    memset(init+20,1,1);
    memset(init+21,0,3);
    memcpy(init+24,&pwdlen,4);
    memcpy(init+28,pwd,pwdlen);
    memcpy(init+t1,&saltlen,4);
    memcpy(init+t1+4,salt,saltlen);
    memset(init+t2,0,8);
    blake2bXto64(init,vars.H0,t2+8);
    pthread_t t[p];
    Argon2iThreadParam tp[p];
    vars.waitCntInit = p-1;
    vars.waitCnt = vars.waitCntInit;
    for(size_t i = 0; i < p; i++)
    {
        tp[i].vars = &vars;
        tp[i].in = i;
        pthread_create(t+i,NULL,argon2iThreadF,(void*)(tp+i));
    }
    for(size_t i = 0; i < p; i++)
    {
        pthread_join(t[i],NULL);
    }
    size_t f = vars.m4-1;
    for(size_t i = 1; i < p; i++)
    {
        blockXor(vars.B[i][f],vars.B[i][f],vars.B[i-1][f]);
    }
    Hp1024toX(vars.B[p-1][f],(uint8_t*)out,outlen);
    for(size_t i = 0; i < p; i++)
    {
        free(vars.B[i]);
    }
    free(vars.B);
}

void *argon2iThreadF(void* prm)
{
    Block adresses, tmp;
    Block input;
    size_t adrIndex = 2;
    Argon2iThreadParam tp = *((Argon2iThreadParam*)prm);
    size_t i = tp.in;
    size_t ll = tp.vars->ll;
    uint32_t tr = tp.vars->tr;
    size_t m1 = tp.vars->m1;
    size_t m2 = tp.vars->m2;
    size_t m3 = tp.vars->m3;
    size_t m4 = tp.vars->m4;
    size_t q = tp.vars->q;
    Block** B = tp.vars->B;
    uint32_t H0p[18];
    memcpy(H0p,tp.vars->H0,64);
    memset(H0p+16,0,4);
    memcpy(H0p+17,&i,4);
    Hp72to1024((uint64_t*)H0p,B[i][0]);
    memset(H0p+16,1,1);
    Hp72to1024((uint64_t*)H0p,B[i][1]);
    MemCo ij;
    input[0] = 1;
    input[1] = i;
    input[2] = 0;
    input[3] = q;
    input[4] = tr;
    input[5] = 1;
    input[6] = 1;
    for(int k = 7; k < ARGON2I_QWORDS_IN_BLOCK; k++)
    {
        input[k] = 0;
    }
    G0(tmp,input);
    G0(adresses,tmp);
    for(size_t j = 2; j < m1; j++)
    {
        if(adrIndex == 128)
        {
            input[6]++;
            G0(tmp,input);
            G0(adresses,tmp);
            adrIndex = 0;
        }
        Gi(B[i][j],B[i][j-1],B[i][phi0(j,&adrIndex,adresses)]);
    }
    threadWait(&(tp.vars->waitMtx),&(tp.vars->waitCnd),&(tp.vars->waitCnt),tp.vars->waitCntInit);
    input[2] = 1;
    input[6] = 1;
    G0(tmp,input);
    G0(adresses,tmp);
    adrIndex = 0;
    for(size_t j = m1; j < m2; j++)
    {
        if(adrIndex == 128)
        {
            input[6]++;
            G0(tmp,input);
            G0(adresses,tmp);
            adrIndex = 0;
        }
        ij = phi(j,1,i,1,ll,m1,m3,m4,&adrIndex,adresses);
        Gi(B[i][j],B[i][j-1],B[ij.i][ij.j]);
    }
    threadWait(&(tp.vars->waitMtx),&(tp.vars->waitCnd),&(tp.vars->waitCnt),tp.vars->waitCntInit);
    input[2] = 2;
    input[6] = 1;
    G0(tmp,input);
    G0(adresses,tmp);
    adrIndex = 0;
    for(size_t j = m2; j < m3; j++)
    {
        if(adrIndex == 128)
        {
            input[6]++;
            G0(tmp,input);
            G0(adresses,tmp);
            adrIndex = 0;
        }
        ij = phi(j,1,i,2,ll,m1,m3,m4,&adrIndex,adresses);
        Gi(B[i][j],B[i][j-1],B[ij.i][ij.j]);
    }
    threadWait(&(tp.vars->waitMtx),&(tp.vars->waitCnd),&(tp.vars->waitCnt),tp.vars->waitCntInit);
    input[2] = 3;
    input[6] = 1;
    G0(tmp,input);
    G0(adresses,tmp);
    adrIndex = 0;
    for(size_t j = m3; j < m4; j++)
    {
        if(adrIndex == 128)
        {
            input[6]++;
            G0(tmp,input);
            G0(adresses,tmp);
            adrIndex = 0;
        }
        ij = phi(j,1,i,3,ll,m1,m3,m4,&adrIndex,adresses);
        Gi(B[i][j],B[i][j-1],B[ij.i][ij.j]);
    }
    for(uint32_t t = 2; t <= tr; t++)
    {
        threadWait(&(tp.vars->waitMtx),&(tp.vars->waitCnd),&(tp.vars->waitCnt),tp.vars->waitCntInit);
        input[0] = t;
        input[2] = 0;
        input[6] = 1;
        G0(tmp,input);
        G0(adresses,tmp);
        adrIndex = 0;
        ij = phi(0,t,i,0,ll,m1,m3,m4,&adrIndex,adresses);
        G(B[i][0],B[i][m4-1],B[ij.i][ij.j]);
        for(size_t j = 1; j < m1; j++)
        {
            if(adrIndex == 128)
            {
                input[6]++;
                G0(tmp,input);
                G0(adresses,tmp);
                adrIndex = 0;
            }
            ij = phi(j,t,i,0,ll,m1,m3,m4,&adrIndex,adresses);
            G(B[i][j],B[i][j-1],B[ij.i][ij.j]);
        }
        threadWait(&(tp.vars->waitMtx),&(tp.vars->waitCnd),&(tp.vars->waitCnt),tp.vars->waitCntInit);
        input[2] = 1;
        input[6] = 1;
        G0(tmp,input);
        G0(adresses,tmp);
        adrIndex = 0;
        for(size_t j = m1; j < m2; j++) 
        {
            if(adrIndex == 128)
            {
                input[6]++;
                G0(tmp,input);
                G0(adresses,tmp);
                adrIndex = 0;
            }
            ij = phi(j,t,i,1,ll,m1,m3,m4,&adrIndex,adresses);
            G(B[i][j],B[i][j-1],B[ij.i][ij.j]);
        }
        threadWait(&(tp.vars->waitMtx),&(tp.vars->waitCnd),&(tp.vars->waitCnt),tp.vars->waitCntInit);
        input[2] = 2;
        input[6] = 1;
        G0(tmp,input);
        G0(adresses,tmp);
        adrIndex = 0;
        for(size_t j = m2; j < m3; j++)
        {
            if(adrIndex == 128)
            {
                input[6]++;
                G0(tmp,input);
                G0(adresses,tmp);
                adrIndex = 0;
            }
            ij = phi(j,t,i,2,ll,m1,m3,m4,&adrIndex,adresses);
            G(B[i][j],B[i][j-1],B[ij.i][ij.j]);
        }
        threadWait(&(tp.vars->waitMtx),&(tp.vars->waitCnd),&(tp.vars->waitCnt),tp.vars->waitCntInit);
        input[2] = 3;
        input[6] = 1;
        G0(tmp,input);
        G0(adresses,tmp);
        adrIndex = 0;
        for(size_t j = m3; j < m4; j++)
        {
            if(adrIndex == 128)
            {
                input[6]++;
                G0(tmp,input);
                G0(adresses,tmp);
                adrIndex = 0;
            }
            ij = phi(j,t,i,3,ll,m1,m3,m4,&adrIndex,adresses);
            G(B[i][j],B[i][j-1],B[ij.i][ij.j]);
        }
    }
    return NULL;
}
