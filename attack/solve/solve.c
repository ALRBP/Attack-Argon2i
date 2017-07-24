#include <stdlib.h>
#include "solve.h"


void selectS(LGraph G, size_t nds, Set S)
{
    for (size_t n = 0; n < nds; n++)
    {
        S[n] = G[n].posS==1||(G[n].np>0&&(G[n].lay==G[G[n].p2].lay&&G[n].posS>=G[G[n].p2].posS));
    }
}

InstList* getInsts(LGraph G, size_t nds, uint32_t t, Set S, size_t numLayers, size_t numSegs, size_t layers[], size_t *segs[], unsigned g)
{
    InstList* pr = NULL;
    bool b = true, peb[nds];
    size_t l = 0, j = 0;
    for(size_t n = 0; n < nds; n++)
    {
        peb[n] = false;
    }
    for(size_t n = 0; n < nds; n++)
    {
        size_t i = n%g;
        if(i == 0)
        {
            b = true;
            l = 0;
            j = 0;
        }
        buildInst(true,n,G[n].np,G[n].p1,G[n].p2,G[n].p3,false,&pr,peb+n);
        if(b)
        {
            bool next = true;
            doNext:
            for(size_t s = 0; s < numSegs; s++)
            {
                if(segs[l][s+1]-segs[l][s] > j)
                {
                    size_t nd = layers[l] + segs[l][s] + j;
                    if((G[nd].np==0)||(peb[G[nd].p1]&&peb[G[nd].p2]&&((G[nd].np<3)||peb[G[nd].p3])))
                    {
                        buildInst(true,nd,G[nd].np,G[nd].p1,G[nd].p2,G[nd].p3,true,&pr,peb+nd);
                    }
                    next = false;
                }
            }
            if(next)
            {
                if(++l > G[n].lay)
                {
                    b = false;
                    l--;
                }
                else
                {
                    j = 0;
                    goto doNext;
                }
            }
            else
            {
                j++;
            }
            if((((int64_t)l)-((int64_t)(numLayers/t)))>0)
            {
                for(size_t nd = layers[((int64_t)l)-((int64_t)(numLayers/t))]; nd < nds; nd--)
                {
                    if(!S[nd])
                    {
                        buildInst(false,nd,0,0,0,0,true,&pr,peb+nd);
                    }
                }
            }
        }
        else
        {
            Set K = (Set)malloc(nds);
            for(size_t k = 0; k < nds; k++)
            {
                K[k] = S[k];
            }
            for(size_t k = n+1; k <= n+g && k < nds; k++)
            {
                switch(G[k].np)
                {
                    case 3:
                        K[G[k].p3] = true;
                        K[G[k].p1] = true;
                        K[G[k].p2] = true;
                        break;
                    case 2:
                        K[G[k].p1] = true;
                        K[G[k].p2] = true;
                        break;
                }
            }
            for(size_t k = 0; k < nds; k++)
            {
                if(peb[k]&&(!K[k]))
                {
                    buildInst(false,k,0,0,0,0,false,&pr,peb+k);
                }
            }
            free(K);
        }
    }
    rewindList(&pr);
    return pr;
}

void expandS(Set S, size_t n, size_t para, size_t numLayers, size_t layers[])
{
    size_t lll = (layers[numLayers]-layers[numLayers-1])/para;
    for(size_t i = 0; i < para; i++)
    {
        S[n-lll*i-1] = true;
    }
}
