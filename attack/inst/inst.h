#include <stdbool.h>


#ifndef INST
typedef struct Inst
{
    bool i;
    size_t n;
    unsigned np;
    size_t p1;
    size_t p2;
    size_t p3;
    bool b;
}Inst;

typedef struct InstList
{
    Inst i;
    struct InstList* p;
    struct InstList* n;
}InstList;
#define INST
#endif


void buildInst(bool i, size_t n, size_t np, size_t p1, size_t p2, size_t p3, bool b, InstList** pr, bool* pb);

void rmInst(InstList** pr);

void rewindList(InstList** pr);

void freeInsts(InstList* pr);

void cpInsts(InstList* sr, InstList** ds);

void cpInst(Inst i, InstList** pr);

bool isParent(Inst i, size_t n);
