#include <stdlib.h>
#include <string.h>
#include "run.h"


typedef uint64_t *PBlock;


void runAttack(SuperLong H0, InstList* insts, void* out, size_t outlen, size_t ll, size_t count, size_t carret)
{
    PBlock B[count];
    uint32_t H0p[18];
    memcpy(H0p,H0,ARGON2I_SUPER_LONG_SIZE);
                            int cn = 0;
    while(insts)
    {
                            cn++;
        if(insts->i.i)
        {
            B[insts->i.n] = (PBlock)malloc(ARGON2I_BLOCK_SIZE);
            switch(insts->i.np)
            {
                case 0:
                    memcpy(H0p+16,&(insts->i.p2),4);
                    memcpy(H0p+17,&(insts->i.p3),4);
                    Hp72to1024((uint64_t*)H0p,B[insts->i.n]);
                    break;
                case 2:
                    Gi(B[insts->i.n],B[insts->i.p1],B[insts->i.p2]);
                    break;
                case 3:
                    Ge(B[insts->i.n],B[insts->i.p1],B[insts->i.p2],B[insts->i.p3]);
                    break;
            }
        }
        else
        {
            free(B[insts->i.n]);
        }
        insts = insts->n;
    }
    size_t last = count-1;
    for(size_t i = 1; i < ll; i++)
    {
        blockXor(B[last-carret*i],B[last-carret*i],B[last-carret*(i-1)]);
        free(B[last-carret*(i-1)]);
    }
    Hp1024toX(B[last-carret*(ll-1)],(uint8_t*)out,outlen);
    free(B[last-carret*(ll-1)]);
}

double costAttack(InstList* insts, double R)
{
    unsigned inMem = 0;
    double cost = 0.0;
    while(insts)
    {
        if(insts->i.i)
        {
            inMem++;
            cost+= inMem+R;
        }
        else
        {
            inMem--;
        }
        insts = insts->n;
    }
    return cost;
}
