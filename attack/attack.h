#include <stdint.h>


#ifndef ATTACK_ARGON2I
#ifndef INST
typedef struct InstList InstList;
#endif
#ifndef GRAPH
typedef struct LGraph LGraph;
#endif
#ifndef SOLVE
typedef struct AttackParams
{
    size_t lay;
    size_t seg;
    unsigned g;
    unsigned d;
}AttackParams;
#endif

typedef struct AttackData
{
    LGraph* graph;
    InstList* insts;
    InstList* instsForPara;
    InstList* instsRaw;
    double quality;
    size_t ll;
    size_t mem;
    size_t iters;
    size_t count;
    size_t carret;
    size_t para;
    size_t gap;
    AttackParams prm;
}AttackData;

typedef struct AttackDataParallel
{
    InstList** insts;
    InstList** instsRaw;
    double quality;
    size_t ll;
    size_t mem;
    size_t iters;
    size_t count;
    size_t carret;
    size_t p;
    AttackParams prm;
}AttackDataParallel;

typedef struct AttackStat
{
    double rawVsStd;
    double rawVsMon;
    double optVsStd;
    double optVsMon;
    double mthVsStd;
    double mthVsMon;
    double rprVsStd;
    double rprVsMon;
    double parVsStd;
    double parVsMon;
}AttackStat;

typedef struct AttackQuickStat
{
    AttackParams npar;
    AttackParams para;
    double nprVsStd;
    double nprVsMon;
    double parVsStd;
    double parVsMon;
}AttackQuickStat;


AttackData attackPrep(size_t p, size_t mem, uint32_t iters, double R);

AttackDataParallel attackPrepParallel(size_t p, size_t mem, uint32_t iters, double R);

AttackDataParallel attackParallelize(AttackData data, double R);

AttackStat attackGetStat(AttackData data, AttackDataParallel datap, AttackDataParallel datam, double R);

AttackQuickStat attackFastStat(size_t p, size_t mem, uint32_t iters, double R);

void attackRun(AttackData data, const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, void* out, size_t outlen);

void attackRunParallel(AttackDataParallel data, const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, void* out, size_t outlen);

void attackClean(AttackData data);

void attackCleanParallel(AttackDataParallel data);

double attackCost(AttackData data, double R);

double attackCostParallel(AttackDataParallel data, double R);

double standardCost(size_t p, size_t mem, uint32_t iters, double R);

double standardCostMono(size_t mem, uint32_t iters, double R);
#define ATTACK_ARGON2I
#endif
