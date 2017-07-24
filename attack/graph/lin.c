#include "graph.h"


size_t getLayer(size_t j, size_t layers[]);

size_t getIndex(NdCo c, size_t layers[], size_t para, size_t q);


void linGraph(Graph g, size_t layers[], size_t para, size_t q, size_t nds, LGraph h)
{
    NdCo c;
    c.t = 1;
    for(size_t i = 0; i < para; i++)
    {
        c.i = i;
        c.j = 0;
        size_t index = getIndex(c,layers,para,q);
        h[index].c = c;
        h[index].np = 0;
        h[index].p1 = 0;
        h[index].p2 = 0;
        h[index].p3 = i;
        c.j = 1;
        index = getIndex(c,layers,para,q);
        h[index].c = c;
        h[index].np = 0;
        h[index].p1 = 0;
        h[index].p2 = 1;
        h[index].p3 = i;
        
    }
    for(size_t n = 0; n < nds-2*para; n++)
    {
        size_t index = getIndex(g[n].self,layers,para,q);
        h[index].c = g[n].self;
        h[index].p1 = getIndex(g[n].p1,layers,para,q);
        h[index].p2 = getIndex(g[n].p2,layers,para,q);
        if(g[n].self.t > 1)
        {
            h[index].np = 3;
            h[index].p3 = getIndex(g[n].p3,layers,para,q);
        }
        else
        {
            h[index].np = 2;
            h[index].p3 = 0;
        }
    }
}

void setLayers(LGraph g, size_t nds, size_t layers[])
{
    for(size_t n = 0; n < nds; n++)
    {
        g[n].lay = getLayer(n,layers);
        g[n].posL = n - layers[g[n].lay];
    }
}

void setSegments(LGraph g, size_t nds, size_t *segs[])
{
    for(size_t n = 0; n < nds; n++)
    {
        g[n].seg = getLayer(g[n].posL,segs[g[n].lay]);
        g[n].posS = segs[g[n].lay][g[n].seg+1]-g[n].posL;
    }
}

size_t getIndex(NdCo c, size_t layers[], size_t para, size_t q)
{
    size_t l = getLayer(c.j,layers);
    size_t lineSize = layers[l+1]-layers[l];
    size_t ans = (c.t-1)*q;
    ans+= layers[l]*para;
    ans+= c.i*lineSize;
    return ans + c.j-layers[l];
}

size_t getLayer(size_t j, size_t layers[])
{
    size_t l = 0;
    while(layers[l+1] <= j)
    {
        l++;
    }
    return l;
}
