#include <stdlib.h>
#include "solve.h"


InstList** getInstsParallel(LGraph G, size_t nds, size_t ll, uint32_t t, Set S, size_t numLayers, size_t numSegs, size_t layers[], size_t *segs[], unsigned g, Set Z)
{
    size_t p = ll+numSegs;
    InstList** ans = (InstList**)calloc(p,sizeof(InstList*));
    bool b = true, peb[nds][p+1], usf[nds];
    size_t l = 0, j = 0;
    for(size_t i = 0; i < nds; i++)
    {
        for(size_t j = 0; j <= p; j++)
        {
            peb[i][j] = false;
        }
        usf[i] = false;
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
        if(!peb[n][G[n].c.i])
        {
            if(peb[n][p]||usf[n]||!((G[n].np==0)||(peb[G[n].p1][G[n].c.i]&&peb[G[n].p2][G[n].c.i]&&((G[n].np<3)||peb[G[n].p3][G[n].c.i]))))
            {
                for(size_t i = 0; i < p; i++)
                {
                    buildInst(true,0,0,0,0,0,true,ans+i,NULL);
                }
                for(size_t i = 0; i < nds; i++)
                {
                    for(size_t j = 0; j < p; j++)
                    {
                        peb[i][j] = peb[i][p];
                    }
                    usf[i] = false;
                }
            }
            if(!peb[n][G[n].c.i])
            {
                buildInst(true,n,G[n].np,G[n].p1,G[n].p2,G[n].p3,false,ans+G[n].c.i,peb[n]+p);
                peb[n][G[n].c.i] = true;
            }
        }
        if(b)
        {
            bool next = true;
            doNext:
            for(size_t s = 0; s < numSegs; s++)
            {
                if(segs[l][s+1]-segs[l][s] > j)
                {
                    size_t nd = layers[l] + segs[l][s] + j;
                    if(!peb[nd][ll+G[nd].seg]&&((G[nd].np==0)||(peb[G[nd].p1][p]&&peb[G[nd].p2][p]&&((G[nd].np<3)||peb[G[nd].p3][p]))))
                    {
                        if(peb[nd][p]||usf[nd]||!((G[nd].np==0)||(peb[G[nd].p1][ll+G[nd].seg]&&peb[G[nd].p2][ll+G[nd].seg]&&((G[nd].np<3)||peb[G[nd].p3][ll+G[nd].seg]))))
                        {
                            for(size_t i = 0; i < p; i++)
                            {
                                buildInst(true,0,0,0,0,0,true,ans+i,NULL);
                            }
                            for(size_t i = 0; i < nds; i++)
                            {
                                for(size_t j = 0; j < p; j++)
                                {
                                    peb[i][j] = peb[i][p];
                                }
                                usf[i] = false;
                            }
                        }
                        if(!peb[nd][ll+G[nd].seg])
                        {
                            buildInst(true,nd,G[nd].np,G[nd].p1,G[nd].p2,G[nd].p3,false,ans+ll+G[nd].seg,peb[nd]+p);
                            peb[nd][ll+G[nd].seg] = true;
                        }
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
                    if(!S[nd]&&peb[nd][p])
                    {
                        for(size_t i = 0; i < p; i++)
                        {
                            buildInst(false,nd,0,0,0,0,false,ans+i,NULL);
                            peb[nd][i] = false;
                        }
                        peb[nd][p] = false;
                        usf[nd] = true;
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
                if(peb[k][p]&&(!K[k]))
                {
                    for(size_t i = 0; i < p; i++)
                    {
                        buildInst(false,k,0,0,0,0,false,ans+i,NULL);
                        peb[k][i] = false;
                    }
                    peb[k][p] = false;
                    usf[k] = true;
                }
            }
            free(K);
        }
    }
    for(size_t k = 0; k < nds; k++)
    {
        if(peb[k][p]&&!Z[k])
        {
            for(size_t i = 0; i < p; i++)
            {
                buildInst(false,k,0,0,0,0,false,ans+i,NULL);
            }
        }
    }
    for(size_t i = 0; i < p; i++)
    {
        rewindList(ans+i);
    }
    return ans;
}

InstList** parallelize(InstList* ins, size_t nds, LGraph G, size_t gap, size_t minP, size_t maxP)
{
    InstList** ans = (InstList**)calloc(maxP,sizeof(InstList*));
    bool peb[maxP][nds], usf[nds];
    size_t order[maxP], lst = maxP;
    unsigned len[maxP];
    for(size_t i = 0; i < maxP; i++)
    {
        for(size_t j = 0; j < nds; j++)
        {
            peb[i][j] = false;
        }
        order[i] = i;
        len[i] = 0;
    }
    for(size_t i = 0; i < nds; i++)
    {
        usf[i] = false;
    }
    bool td = true;
    while(ins)
    {
        if(ins->i.i)
        {
            if(!(usf[ins->i.n]||(td&&!ins->i.b&&G[ins->i.n].posL==0)))
            {
                size_t i = 0, j;
                while(i<lst)
                {
                    j=order[i];
                    if((G[ins->i.n].np==0)||(peb[j][G[ins->i.n].p1]&&peb[j][G[ins->i.n].p2]&&((G[ins->i.n].np<3)||peb[j][G[ins->i.n].p3])))
                    {
                        cpInst(ins->i,ans+j);
                        ans[j]->i.b = false;
                        peb[j][ins->i.n] = true;
                        len[j]++;
                        for(; i<maxP-1; i++)
                        {
                            if(len[order[i]]>len[order[i+1]]||(len[order[i]]==len[order[i+1]]&&order[i]>order[i+1]))
                            {
                                size_t tmp = order[i+1];
                                order[i+1] = order[i];
                                order[i] = tmp;
                            }
                            else
                            {
                                break;
                            }
                        }
                        size_t mxl = len[order[maxP-minP]]+gap;
                        for(lst = maxP-minP+1; lst < maxP; lst++)
                        {
                            if(len[order[lst]] > mxl)
                            {
                                break;
                            }
                        }
                        td = true;
                        goto next;
                    }
                    i++;
                }
            }
            for(size_t k = 0; k < nds; k++)
            {
                size_t j = 0;
                while(!peb[0][k] && j<maxP)
                {
                    peb[0][k] = peb[j][k];
                    j++;
                }
            }
            buildInst(true,0,0,0,0,0,true,ans,NULL);
            len[0] = 0;
            order[0] = 0;
            lst = maxP;
            for(size_t i = 1; i < maxP; i++)
            {
                buildInst(true,0,0,0,0,0,true,ans+i,NULL);
                len[i] = 0;
                order[i] = i;
                for(size_t k = 0; k < nds; k++)
                {
                    peb[i][k] = peb[0][k];
                }
            }
            for(size_t i = 0; i < nds; i++)
            {
                usf[i] = false;
            }
            td = false;
        }
        else
        {
            for(size_t i = 0; i < maxP; i++)
            {
                cpInst(ins->i,ans+i);
                ans[i]->i.b = false;
                peb[i][ins->i.n] = false;
            }
            usf[ins->i.n] = true;
        }
        next:
        if(td)
        {
            ins = ins->n;
        }
    }
    for(size_t i = 0; i < maxP; i++)
    {
        rewindList(ans+i);
    }
    return ans;
}
