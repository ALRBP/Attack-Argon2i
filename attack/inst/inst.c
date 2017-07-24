#include <stdlib.h>
#include "inst.h"

void buildInst(bool i, size_t n, size_t np, size_t p1, size_t p2, size_t p3, bool b, InstList** pr, bool* pb)
{
    if(!pb || *pb != i)
    {
        InstList* tmp = *pr;
        *pr = (InstList*)malloc(sizeof(InstList));
        (*pr)->i.i = i;
        (*pr)->i.n = n;
        (*pr)->i.np = np;
        (*pr)->i.p1 = p1;
        (*pr)->i.p2 = p2;
        (*pr)->i.p3 = p3;
        (*pr)->i.b = b;
        (*pr)->p = tmp;
        if(tmp)
        {
            (*pr)->n = tmp->n;
            if(tmp->n)
            {
                tmp->n->p = *pr;
            }
            tmp->n = *pr;
        }
        else
        {
            (*pr)->n = NULL;
        }
        if(pb)
        {
            *pb = i;
        }
    }
}

void rewindList(InstList** pr)
{
    if(*pr)
    {
        while((*pr)->p)
        {
            *pr = (*pr)->p;
        }
    }
}

void rmInst(InstList** pr)
{
    if((*pr)->p)
    {
        (*pr)->p->n = (*pr)->n;
    }
    if((*pr)->n)
    {
        (*pr)->n->p = (*pr)->p;
    }
    InstList* tmp = *pr;
    if(!(*pr)->p)
    {
        *pr = (*pr)->n;
    }
    else
    {
        *pr = (*pr)->p;
    }
    free(tmp);
}

void freeInsts(InstList* pr)
{
    while(pr)
    {
        InstList* tmp = pr;
        pr = pr->n;
        free(tmp);
    }
}

void cpInsts(InstList* sr, InstList** ds)
{
    *ds = NULL;
    while(sr)
    {
        cpInst(sr->i,ds);
        sr = sr->n;
    }
    rewindList(ds);
}

void cpInst(Inst i, InstList** pr)
{
    InstList* tmp = *pr;
    *pr = (InstList*)malloc(sizeof(InstList));
    (*pr)->i = i;
    (*pr)->p = tmp;
    if(tmp)
    {
        (*pr)->n = tmp->n;
        if(tmp->n)
        {
            tmp->n->p = *pr;
        }
        tmp->n = *pr;
    }
    else
    {
        (*pr)->n = NULL;
    }
}

bool isParent(Inst i, size_t n)
{
    return i.np > 0 && (i.p1 == n || i.p2 == n || (i.np == 3 && i.p3 == n));
}
