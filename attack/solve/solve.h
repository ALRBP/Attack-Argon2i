#include <stdbool.h>
#include <stdint.h>
#include "../graph/graph.h"
#include "../inst/inst.h"


typedef bool *Set;

#ifndef SOLVE
typedef struct AttackParams
{
    size_t lay;
    size_t seg;
    unsigned g;
    unsigned d;
}AttackParams;
#define SOLVE
#endif


AttackParams searchForParameters(Graph G, size_t n, uint32_t t, double R, size_t parallelism, bool precise, bool para);

void getLayers(size_t numLayers, size_t nOverP, size_t layers[]);

void getSegments(size_t numSegs, size_t numLayers, size_t layers[], size_t *segs[]);

void morphLayers(size_t para, size_t numLayers, size_t layers[]);

void solveLayers(size_t ly, size_t nmverP, size_t layers[]);

void ensureFree(InstList* pr, size_t nds, Set Z);

void cleanUseless(InstList* pr, size_t nds);

void reduceMem(InstList* pr, size_t nds, LGraph G, double R);

void calcLater(InstList* pr, size_t nds);

void freeEarlier(InstList* pr, size_t nds);

void selectS(LGraph G, size_t nds, Set S);

InstList* getInsts(LGraph G, size_t nds, uint32_t t, Set S, size_t numLayers, size_t numSegs, size_t layers[], size_t *segs[], unsigned g);

InstList** getInstsParallel(LGraph G, size_t nds, size_t ll, uint32_t t, Set S, size_t numLayers, size_t numSegs, size_t layers[], size_t *segs[], unsigned g, Set Z);

InstList** parallelize(InstList* ins, size_t nds, LGraph G, size_t gap, size_t minP, size_t maxP);

void expandS(Set S, size_t n, size_t para, size_t numLayers, size_t layers[]);

double costAttackEst(LGraph G, size_t nds, uint32_t t, Set S, size_t numLayers, size_t numSegs, size_t layers[], size_t *segs[], unsigned g, double R, bool para);

void cleanUselessParallel(InstList** pr, size_t nds, size_t p);

void reduceMemParallel(InstList** pr, size_t nds, size_t p, LGraph G, double R);

void freeEarlierParallel(InstList** pr, size_t nds, size_t p);

void calcLaterParallel(InstList** pr, size_t nds, size_t p);
