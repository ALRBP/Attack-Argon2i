#include <stdlib.h>
#include "solve.h"


void ensureFree(InstList* pr, size_t nds, Set Z)
{
    for(size_t n = 0; n < nds; n++)
    {
        if(!Z[n])
        {
            InstList* ins = pr, *insrtPoint;
            bool toFree = false;
            while(ins)
            {
                if(ins->i.n == n)
                {
                    if(ins->i.i)
                    {
                        toFree = true;
                        insrtPoint = ins;
                    }
                    else
                    {
                        toFree = false;
                    }
                }
                else if(toFree && isParent(ins->i,n))
                {
                    insrtPoint = ins;
                }
                ins = ins->n;
            }
            if(toFree)
            {
                buildInst(false,n,0,0,0,0,insrtPoint->i.b,&insrtPoint,NULL);
            }
        }
    }
}

void cleanUseless(InstList* pr, size_t nds)
{
    for(size_t n = nds-1; n < nds; n--)
    {
        InstList* ins = pr, *clc;
        bool rm = false;
        while(ins)
        {
            if(ins->i.n == n)
            {
                if(ins->i.i)
                {
                    clc = ins;
                    rm = true;
                }
                else
                {
                    if(rm)
                    {
                        rmInst(&clc);
                        rmInst(&ins);
                    }
                }
            }
            else if(rm && isParent(ins->i,n))
            {
                rm = false;
            }
            ins = ins->n;
        }
    }
}

void reduceMem(InstList* pr, size_t nds, LGraph G, double R)
{
    for(size_t n = nds-1; n < nds; n--)
    {
        InstList* ins = pr, *beg;
        bool w = false;
        bool* peb = (bool*)calloc(nds,1);
        unsigned ws = 0, mem = 0;
        while(ins)
        {
            if(isParent(ins->i,n))
            {
                if(w)
                {
                    if(G[n].np == 0 || (peb[G[n].p1] && peb[G[n].p2] && (G[n].np < 3 || peb[G[n].p3])))
                    {
                        if(R + mem < ws-1)
                        {
                            buildInst(false,n,0,0,0,0,beg->i.b,&beg,NULL);
                            buildInst(true,n,G[n].np,G[n].p1,G[n].p2,G[n].p3,ins->p->i.b,&(ins->p),NULL);
                        }
                    }
                    beg = ins;
                    ws = 0;
                }
                else
                {
                    beg = ins;
                    w = true;
                    ws = 0;
                }
            }
            else if(ins->i.n == n && !ins->i.i)
            {
                w = false;
            }
            peb[ins->i.n] = ins->i.i;
            if(ins->i.i)
            {
                mem++;
                ws++;
            }
            else
            {
                mem--;
            }
            ins = ins->n;
        }
        free(peb);
    }
}

void freeEarlier(InstList* pr, size_t nds)
{
    for(size_t n = 0; n < nds; n++)
    {
        InstList* ins = pr, *lst;
        while(ins)
        {
            if(ins->i.i)
            {
                if(isParent(ins->i,n))
                {
                    lst = ins;
                }
            }
            else if(ins->i.n == n && !(isParent(ins->p->i,n)))
            {
                buildInst(false,n,0,0,0,0,lst->i.b,&lst,NULL);
                rmInst(&ins);
            }
            ins = ins->n;
        }
    }
}

void calcLater(InstList* pr, size_t nds)
{
    for(size_t n = nds-1; n < nds; n--)
    {
        InstList* ins = pr->n, *clc;
        bool w = false;
        while(ins)
        {
            if(ins->i.i && ins->i.n == n)
            {
                clc = ins;
                w = true;
            }
            else if(w && (isParent(ins->i,n) || (!ins->i.i && isParent(clc->i,ins->i.n))))
            {
                w = false;
                if(ins->p->i.n != n)
                {
                    cpInst(clc->i,&(ins->p));
                    rmInst(&clc);
                }
            }
            ins = ins->n;
        }
    }
}

void cleanUselessParallel(InstList** pr, size_t nds, size_t p)
{
    for(size_t n = nds-1; n < nds; n--)
    {
        for(size_t i = 0; i < p; i++)
        {
            InstList* ins = pr[i], *clc;
            bool rm = false;
            while(ins)
            {
                if(ins->i.b)
                {
                    rm = false;
                }
                else if(ins->i.n == n)
                {
                    if(ins->i.i)
                    {
                        clc = ins;
                        rm = true;
                    }
                    else
                    {
                        if(rm)
                        {
                            rmInst(&clc);
                            rmInst(&ins);
                        }
                    }
                }
                else if(rm && isParent(ins->i,n))
                {
                    rm = false;
                }
                ins = ins->n;
            }
        }
    }
}

void freeEarlierParallel(InstList** pr, size_t nds, size_t p)
{
    for(size_t n = 0; n < nds; n++)
    {
        for(size_t i = 0; i < p; i++)
        {
            InstList* ins = pr[i], *lst;
            while(ins)
            {
                if(ins->i.b)
                {
                    lst = ins;
                }
                else if(ins->i.i)
                {
                    if(isParent(ins->i,n))
                    {
                        lst = ins;
                    }
                }
                else if(ins->i.n == n && !(isParent(ins->p->i,n)))
                {
                    buildInst(false,n,0,0,0,0,false,&lst,NULL);
                    rmInst(&ins);
                }
                ins = ins->n;
            }
        }
    }
}

void calcLaterParallel(InstList** pr, size_t nds, size_t p)
{
    for(size_t n = nds-1; n < nds; n--)
    {
        for(size_t i = 0; i < p; i++)
        {
            InstList* ins = pr[i]->n, *clc;
            bool w = false;
            while(ins)
            {
                if(ins->i.b)
                {
                    if(w)
                    {
                        w = false;
                        if(ins->p->i.n != n)
                        {
                            cpInst(clc->i,&(ins->p));
                            rmInst(&clc);
                        }
                    }
                }
                else if(ins->i.i && ins->i.n == n)
                {
                    clc = ins;
                    w = true;
                }
                else if(w && (isParent(ins->i,n) || (!ins->i.i && isParent(clc->i,ins->i.n))))
                {
                    w = false;
                    if(ins->p->i.n != n)
                    {
                        cpInst(clc->i,&(ins->p));
                        rmInst(&clc);
                    }
                }
                ins = ins->n;
            }
        }
    }
}
