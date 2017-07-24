#include "../../argon2/argon2i_a.h"
#include "graph.h"


void genGraph(size_t ll, uint32_t iters, size_t q, Graph ret)
{
    size_t n = 0, m1 = q/(ARGON2_SYNC_POINTS*ll);
    Block adresses, input, tmp;
    size_t adrIndex;
    size_t lst = 4*m1-1, m0, m;
    MemCo ij;
    input[3] = q;
    input[4] = iters;
    input[5] = 1;
    for(int k = 7; k < ARGON2I_QWORDS_IN_BLOCK; k++)
    {
        input[k] = 0;
    }
    for(size_t i = 0; i < ll; i++)
    {
        m0 = 0;
        m = m1;
        input[0] = 1;
        input[1] = i;
        input[2] = 0;
        input[6] = 1;
        G0(tmp,input);
        G0(adresses,tmp);
        adrIndex = 2;
        for(size_t j = 2; j < m; j++)
        {
            if(adrIndex == 128)
            {
                input[6]++;
                G0(tmp,input);
                G0(adresses,tmp);
                adrIndex = 0;
            }
            ret[n].self.i = i;
            ret[n].self.j = j;
            ret[n].self.t = 1;
            ret[n].p1.i = i;
            ret[n].p1.j = j-1;
            ret[n].p1.t = 1;
            ret[n].p2.i = i;
            ret[n].p2.j = phi0(j,&adrIndex,adresses);
            ret[n].p2.t = 1;
            n++;
        }
        for(size_t s = 1; s < ARGON2_SYNC_POINTS; s++)
        {
            m0+= m1;
            m+= m1;
            input[2] = s;
            input[6] = 1;
            G0(tmp,input);
            G0(adresses,tmp);
            adrIndex = 0;
            for(size_t j = m0; j < m; j++)
            {
                if(adrIndex == 128)
                {
                    input[6]++;
                    G0(tmp,input);
                    G0(adresses,tmp);
                    adrIndex = 0;
                }
                ij = phi(j,1,i,s,ll,m1,m1*3,m1*4,&adrIndex,adresses);
                ret[n].self.i = i;
                ret[n].self.j = j;
                ret[n].self.t = 1;
                ret[n].p1.i = i;
                ret[n].p1.j = j-1;
                ret[n].p1.t = 1;
                ret[n].p2.i = ij.i;
                ret[n].p2.j = ij.j;
                ret[n].p2.t = 1;
                n++;
            }
        }
        for(uint32_t t = 2; t <= iters; t++)
        {
            m0 = 0;
            m = m1;
            input[0] = t;
            for(uint8_t s = 0; s < ARGON2_SYNC_POINTS; s++)
            {
                input[2] = s;
                input[6] = 1;
                G0(tmp,input);
                G0(adresses,tmp);
                adrIndex = 0;
                for(size_t j = m0; j < m; j++)
                {
                    if(adrIndex == 128)
                    {
                        input[6]++;
                        G0(tmp,input);
                        G0(adresses,tmp);
                        adrIndex = 0;
                    }
                    ij = phi(j,t,i,s,ll,m1,m1*3,m1*4,&adrIndex,adresses);
                    ret[n].self.i = i;
                    ret[n].self.j = j;
                    ret[n].self.t = t;
                    ret[n].p1.i = i;
                    if(j==0)
                    {
                        ret[n].p1.j = lst;
                        ret[n].p1.t = t-1;
                    }
                    else
                    {
                        ret[n].p1.j = j-1;
                        ret[n].p1.t = t;
                    }
                    ret[n].p2.i = ij.i;
                    ret[n].p2.j = ij.j;
                    ret[n].p2.t = ij.j<j?t:t-1;
                    ret[n].p3.i = i;
                    ret[n].p3.j = j;
                    ret[n].p3.t = t-1;
                    n++;
                }
                m0+= m1;
                m+= m1;
            }
        }
    }
}
