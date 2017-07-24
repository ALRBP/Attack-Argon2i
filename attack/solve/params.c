#include <stdlib.h>
#include <math.h>
#include "../../argon2/argon2i_a.h"
#include "solve.h"

#define NUM_DATA_POINTS_LAYERS 5
#define NUM_DATA_POINTS_SEGS 5
#define NUM_DATA_POINTS_G 5
#define PRECISE_RATIO 2


unsigned getD(size_t numLayers, size_t numSegs, size_t *segs[]);


AttackParams searchForParameters(Graph G, size_t n, uint32_t t, double R, size_t parallelism, bool precise, bool para)
{
    AttackParams ans;
    unsigned dpl = NUM_DATA_POINTS_LAYERS;
    unsigned dps = NUM_DATA_POINTS_SEGS;
    unsigned dpg = NUM_DATA_POINTS_G;
    if(precise)
    {
        dpl*= PRECISE_RATIO;
        dps*= PRECISE_RATIO;
        dpg*= PRECISE_RATIO;
    }
    unsigned theoryOptg = pow(n,0.75);
    double theoryOptLayers = pow(n,0.25);
    double theoryOptGap = pow(n,0.25);
    
    unsigned gMin = theoryOptg/4;
    unsigned gMax = n;
    unsigned gStep = (gMax-gMin)/(dpg-1);
    if(gStep == 0)
    {
        gStep = 1;
    }
    double optCost = INFINITY;
    for(unsigned g = gMin; g <= gMax; g+= gStep)
    {
        unsigned layersMin = theoryOptLayers/(4*ARGON2_SYNC_POINTS*t);
        unsigned layersMax = floor(sqrt(g))/(ARGON2_SYNC_POINTS*t);
        if(layersMin == 0)
        {
            layersMin = 1;
        }
        if(layersMax == 0)
        {
            layersMax = 1;
        }
        unsigned layersStep = (layersMax-layersMin)/(dpl-1);
        if(layersStep == 0)
        {
            layersStep = 1;
        }
        layersMin*= ARGON2_SYNC_POINTS*t;
        layersMax*= ARGON2_SYNC_POINTS*t;
        layersStep*= ARGON2_SYNC_POINTS*t;
        LGraph H = (LGraph)malloc(sizeof(LNode)*n);
        for(unsigned layers = layersMin; layers <= layersMax; layers+= layersStep)
        {
            size_t layersTab[layers+1];
            getLayers(layers,n/parallelism,layersTab);
            linGraph(G,layersTab,parallelism,n/t,n,H);
            morphLayers(parallelism,layers,layersTab);
            setLayers(H,n,layersTab);
            unsigned segsMin = n/(layers*floor(sqrt(g))*parallelism);
            unsigned segsMax = n/(layers*(theoryOptGap>7?theoryOptGap/4:1)*parallelism);
            if(segsMax<segsMin)
            {
                segsMin = segsMax;
            }
            if(segsMin == 0)
            {
                segsMin = 1;
            }
            if(segsMax == 0)
            {
                segsMax = 1;
            }
            unsigned segsStep = (segsMax-segsMin)/(dps-1);
            if(segsStep == 0)
            {
                segsStep = 1;
            }
            segsMin*=parallelism;
            segsMax*=parallelism;
            segsStep*=parallelism;
            Set S = (Set)malloc(n);
            for(unsigned segs = segsMin; segs <= segsMax; segs+= segsStep)
            {
                size_t *segsTab[layers];
                for(size_t ly = 0; ly < layers; ly++)
                {
                    segsTab[ly] = (size_t*)malloc(sizeof(size_t)*(segs+1));
                }
                getSegments(segs,layers,layersTab,segsTab);
                setSegments(H,n,segsTab);
                selectS(H,n,S);
                expandS(S,n,parallelism,layers,layersTab);
                double curCost = costAttackEst(H,n,t,S,layers,segs,layersTab,segsTab,g,R,para);
                if(optCost > curCost)
                {
                    ans.lay = layers;
                    ans.seg = segs;
                    ans.g = g;
                    ans.d = getD(layers,segs,segsTab);
                    optCost = curCost;
                }
                for(size_t ly = 0; ly < layers; ly++)
                {
                    free(segsTab[ly]);
                }
            }
            free(S);
        }
        free(H);
    }
    return ans;
}

void getLayers(size_t numLayers, size_t nOverP, size_t layers[])
{
    for(size_t i = 0; i <= numLayers; i++)
    {
        layers[i] = (i*nOverP)/numLayers;
    }
}

void getSegments(size_t numSegs, size_t numLayers, size_t layers[], size_t *segs[])
{
    for(size_t i = 0; i < numLayers; i++)
    {
        size_t ls = layers[i+1] - layers[i];
        for(size_t j = 0; j <= numSegs; j++)
        {
            segs[i][j] = (j*ls)/numSegs;
        }
    }
}

void morphLayers(size_t para, size_t numLayers, size_t layers[])
{
    for(size_t i = 1; i <= numLayers; i++)
    {
        layers[i]*= para;
    }
}

unsigned getD(size_t numLayers, size_t numSegs, size_t *segs[])
{
    unsigned ans = 0;
    for(size_t i = 0; i < numLayers; i++)
    {
        unsigned max = 0;
        for(size_t j = 0; j < numSegs; j++)
        {
            max = 0;
            if(segs[i][j+1]-segs[i][j] > max)
            {
                max = segs[i][j+1]-segs[i][j];
            }
        }
        ans+= max;
    }
    return ans;
}

double costAttackEst(LGraph G, size_t nds, uint32_t t, Set S, size_t numLayers, size_t numSegs, size_t layers[], size_t *segs[], unsigned g, double R, bool para)
{
    unsigned inMem = 0;
    double cost = 0.0;
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
        if(!peb[n])
        {
            peb[n] = true;
            inMem++;
            if(para)
            {
                cost+= R;
            }
            else
            {
                cost+= inMem+R;
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
                    if(!peb[nd]&&((G[nd].np==0)||(peb[G[nd].p1]&&peb[G[nd].p2]&&((G[nd].np<3)||peb[G[nd].p3]))))
                    {
                        peb[nd] = true;
                        inMem++;
                        if(para)
                        {
                            cost+= R;
                        }
                        else
                        {
                            cost+= inMem+R;
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
            if(para)
            {
                cost+= inMem;
            }
            if((((int64_t)l)-((int64_t)(numLayers/t)))>0)
            {
                for(size_t nd = layers[((int64_t)l)-((int64_t)(numLayers/t))]; nd < nds; nd--)
                {
                    if(!S[nd]&&peb[nd])
                    {
                        peb[nd] = false;
                        inMem--;
                    }
                }
            }
        }
        else
        {
            if(para&&G[n].c.i==0)
            {
                cost+= inMem;
            }
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
                    peb[k] = false;
                    inMem--;
                }
            }
            free(K);
        }
    }
    return cost;
}
