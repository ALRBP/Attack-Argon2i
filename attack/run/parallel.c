#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "run.h"


typedef uint64_t *PBlock;

typedef struct AttackThreadParam
{
    InstList* insts;
    SuperLong H0;
    PBlock* B;
    size_t* waitCnt;
    size_t waitCntInit;
    pthread_mutex_t* waitMtx;
    pthread_cond_t* waitCnd;
    size_t* freeCnt;
    pthread_mutex_t* freeMtx;
}AttackThreadParam;


void *attackThreadF(void* prm);


void runAttackParallel(SuperLong H0, InstList** insts, void* out, size_t outlen, size_t ll, size_t count, size_t carret, size_t p)
{
    InstList** inst = (InstList**)malloc(sizeof(InstList*)*p);
    for(size_t i = 0; i < p; i++)
    {
        inst[i] = insts[i];
    }
    PBlock B[count];
    pthread_t t[p];
    AttackThreadParam tp[p];
    size_t waitCnt = p-1;
    pthread_mutex_t waitMtx;
    pthread_cond_t waitCnd;
    pthread_mutex_init(&waitMtx,NULL);
    pthread_cond_init(&waitCnd,NULL);
    size_t freeCnt[count];
    pthread_mutex_t freeMtx[count];
    for(size_t i = 0; i < count; i++)
    {
        freeCnt[i] = waitCnt;
        pthread_mutex_init(freeMtx+i,NULL);
    }
    for(size_t i = 0; i < p; i++)
    {
        tp[i].insts = inst[i];
        memcpy(tp[i].H0,H0,ARGON2I_SUPER_LONG_SIZE);
        tp[i].B = B;
        tp[i].waitCnt = &waitCnt;
        tp[i].waitCntInit = waitCnt;
        tp[i].waitMtx = &waitMtx;
        tp[i].waitCnd = &waitCnd;
        tp[i].freeCnt = freeCnt;
        tp[i].freeMtx = freeMtx;
    }
    for(size_t i = 0; i < p; i++)
    {
        pthread_create(t+i,NULL,attackThreadF,(void*)(tp+i));
    }
    for(size_t i = 0; i < p; i++)
    {
        pthread_join(t[i],NULL);
    }
    size_t last = count-1;
    for(size_t i = 1; i < ll; i++)
    {
        blockXor(B[last-carret*i],B[last-carret*i],B[last-carret*(i-1)]);
        free(B[last-carret*(i-1)]);
    }
    Hp1024toX(B[last-carret*(ll-1)],(uint8_t*)out,outlen);
    free(B[last-carret*(ll-1)]);
    free(inst);
}

void *attackThreadF(void* prm)
{
    AttackThreadParam d = *((AttackThreadParam*)prm);
    uint32_t H0p[18];
    memcpy(H0p,d.H0,ARGON2I_SUPER_LONG_SIZE);
    while(d.insts)
    {
        if(d.insts->i.b)
        {
            threadWait(d.waitMtx,d.waitCnd,d.waitCnt,d.waitCntInit);
        }
        else
        {
            if(d.insts->i.i)
            {
                d.B[d.insts->i.n] = (PBlock)malloc(ARGON2I_BLOCK_SIZE);
                switch(d.insts->i.np)
                {
                    case 0:
                        memcpy(H0p+16,&(d.insts->i.p2),4);
                        memcpy(H0p+17,&(d.insts->i.p3),4);
                        Hp72to1024((uint64_t*)H0p,d.B[d.insts->i.n]);
                        break;
                    case 2:
                        Gi(d.B[d.insts->i.n],d.B[d.insts->i.p1],d.B[d.insts->i.p2]);
                        break;
                    case 3:
                        Ge(d.B[d.insts->i.n],d.B[d.insts->i.p1],d.B[d.insts->i.p2],d.B[d.insts->i.p3]);
                        break;
                }
            }
            else
            {
                pthread_mutex_lock(d.freeMtx+d.insts->i.n);
                if(d.freeCnt[d.insts->i.n])
                {
                    d.freeCnt[d.insts->i.n]--;
                }
                else
                {
                    d.freeCnt[d.insts->i.n] = d.waitCntInit;
                    free(d.B[d.insts->i.n]);
                }
                pthread_mutex_unlock(d.freeMtx+d.insts->i.n);
            }
        }
        d.insts = d.insts->n;
    }
    return NULL;
}

double costAttackParallel(InstList** insts, size_t count, size_t p, double R)
{
    InstList** inst = (InstList**)malloc(sizeof(InstList*)*p);
    bool c = true;
    unsigned inMem = 0;
    double cost = 0.0;
    size_t waitCnt = p-1;
    size_t freeCnt[count];
    bool rd[p], go[p];
    for(size_t i = 0; i < count; i++)
    {
        freeCnt[i] = p-1;
    }
    for(size_t i = 0; i < p; i++)
    {
        rd[i] = true;
        go[i] = false;
        inst[i] = insts[i];
    }
    while(c)
    {
        cost+= inMem;
        c = false;
        for(size_t i = 0; i < p; i++)
        {
            bool r = true;
            while(r)
            {
                r = false;
                if(inst[i])
                {
                    c = true;
                    if(inst[i]->i.b)
                    {
                        if(rd[i])
                        {
                            if(waitCnt)
                            {
                                waitCnt--;
                                go[i] = false;
                                rd[i] = false;
                            }
                            else
                            {
                                waitCnt = p-1;
                                for(size_t j = 0; j < p; j++)
                                {
                                    go[j] = true;
                                }
                                inst[i] = inst[i]->n;
                                go[i] = false;
                            }
                        }
                        else if(go[i])
                        {
                            inst[i] = inst[i]->n;
                            go[i] = false;
                            rd[i] = true;
                        }
                    }
                    else
                    {
                        if(inst[i]->i.i)
                        {
                            inMem++;
                            cost+= R;
                        }
                        else
                        {
                            if(freeCnt[inst[i]->i.n])
                            {
                                freeCnt[inst[i]->i.n]--;
                            }
                            else
                            {
                                freeCnt[inst[i]->i.n] = p-1;
                                inMem--;
                            }
                            r = true;
                        }
                        inst[i] = inst[i]->n;
                    }
                }
            }
        }
    }
    free(inst);
    return cost;
}
