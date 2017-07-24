#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../argon2/blake2/blake2b.h"
#include "solve/solve.h"
#include "run/run.h"
#include "attack.h"


AttackData attackPrep(size_t p, size_t mem, uint32_t iters, double R)
{
    AttackData ans;
    ans.ll = p;
    ans.mem = mem;
    ans.iters = iters;
    ans.count = mem*iters;
    Graph G = (Graph)malloc(sizeof(Node)*(ans.count-2*p));
    genGraph(p,iters,mem,G);
    ans.prm = searchForParameters(G,ans.count,iters,R,p,true,false);
    size_t layers[ans.prm.lay], *segments[ans.prm.lay];
    for(size_t ly = 0; ly < ans.prm.lay; ly++)
    {
        segments[ly] = (size_t*)malloc(sizeof(size_t)*(ans.prm.seg+1));
    }
    getLayers(ans.prm.lay,ans.count/p,layers);
    ans.graph = (LGraph*)malloc(sizeof(LGraph*));
    *(ans.graph) = (LGraph)malloc(sizeof(LNode)*ans.count);
    linGraph(G,layers,p,mem,ans.count,*(ans.graph));
    free(G);
    morphLayers(p,ans.prm.lay,layers);
    getSegments(ans.prm.seg,ans.prm.lay,layers,segments);
    setLayers(*(ans.graph),ans.count,layers);
    setSegments(*(ans.graph),ans.count,segments);
    Set S = (Set)malloc(ans.count);
    selectS(*(ans.graph),ans.count,S);
    expandS(S,ans.count,p,ans.prm.lay,layers);
    ans.insts = getInsts(*(ans.graph),ans.count,iters,S,ans.prm.lay,ans.prm.seg,layers,segments,ans.prm.g);
    free(S);
    for(size_t ly = 0; ly < ans.prm.lay; ly++)
    {
        free(segments[ly]);
    }
    cpInsts(ans.insts,&(ans.instsRaw));
    Set Z = (Set)calloc(ans.count,1);
    expandS(Z,ans.count,p,ans.prm.lay,layers);
    ensureFree(ans.insts,ans.count,Z);
    free(Z);
    cleanUseless(ans.insts,ans.count);
    freeEarlier(ans.insts,ans.count);
    cpInsts(ans.insts,&(ans.instsForPara));
    calcLater(ans.insts,ans.count);
    reduceMem(ans.insts,ans.count,*(ans.graph),R);
    ans.carret = (layers[ans.prm.lay]-layers[ans.prm.lay-1])/p;
    ans.para = p+ans.prm.seg;
    ans.gap = ans.count/(ans.prm.lay*p);
    ans.quality = standardCost(p,mem,iters,R)/costAttack(ans.insts,R);
    return ans;
}

AttackDataParallel attackPrepParallel(size_t p, size_t mem, uint32_t iters, double R)
{
    AttackDataParallel ans;
    ans.ll = p;
    ans.mem = mem;
    ans.iters = iters;
    ans.count = mem*iters;
    Graph G = (Graph)malloc(sizeof(Node)*(ans.count-2*p));
    genGraph(p,iters,mem,G);
    ans.prm = searchForParameters(G,ans.count,iters,R,p,true,true);
    size_t layers[ans.prm.lay], *segments[ans.prm.lay];
    for(size_t ly = 0; ly < ans.prm.lay; ly++)
    {
        segments[ly] = (size_t*)malloc(sizeof(size_t)*(ans.prm.seg+1));
    }
    getLayers(ans.prm.lay,ans.count/p,layers);
    LGraph H = (LGraph)malloc(sizeof(LNode)*ans.count);
    linGraph(G,layers,p,mem,ans.count,H);
    free(G);
    morphLayers(p,ans.prm.lay,layers);
    getSegments(ans.prm.seg,ans.prm.lay,layers,segments);
    setLayers(H,ans.count,layers);
    setSegments(H,ans.count,segments);
    Set S = (Set)malloc(ans.count);
    selectS(H,ans.count,S);
    expandS(S,ans.count,p,ans.prm.lay,layers);
    Set Z = (Set)calloc(ans.count,1);
    expandS(Z,ans.count,p,ans.prm.lay,layers);
    ans.insts = getInstsParallel(H,ans.count,p,iters,S,ans.prm.lay,ans.prm.seg,layers,segments,ans.prm.g,Z);
    free(Z);
    free(S);
    free(H);
    for(size_t ly = 0; ly < ans.prm.lay; ly++)
    {
        free(segments[ly]);
    }
    ans.p = p+ans.prm.seg;
    ans.instsRaw = (InstList**)calloc(ans.p,sizeof(InstList*));
    for(size_t i = 0; i < ans.p; i++)
    {
        cpInsts(ans.insts[i],ans.instsRaw+i);
    }
    cleanUselessParallel(ans.insts,ans.count,p);
    freeEarlierParallel(ans.insts,ans.count,p);
    calcLaterParallel(ans.insts,ans.count,p);
    ans.carret = (layers[ans.prm.lay]-layers[ans.prm.lay-1])/p;
    ans.quality = standardCost(p,mem,iters,R)/costAttackParallel(ans.insts,ans.count,ans.p,R);
    return ans;
}

AttackDataParallel attackParallelize(AttackData data, double R)
{
    AttackDataParallel ans;
    ans.ll = data.ll;
    ans.mem = data.mem;
    ans.iters = data.iters;
    ans.ll = data.ll;
    ans.count = data.count;
    ans.carret = data.carret;
    ans.p = data.para;
    ans.instsRaw = NULL;
    ans.prm = data.prm;
    ans.insts = parallelize(data.instsForPara,data.count,*data.graph,data.gap,data.ll,data.para);
    ans.quality = standardCost(data.ll,data.mem,data.iters,R)/costAttackParallel(ans.insts,ans.count,ans.p,R);
    return ans;
}

AttackStat attackGetStat(AttackData data, AttackDataParallel datam, AttackDataParallel datap, double R)
{
    AttackStat ans;
    double rawCost = costAttack(data.instsRaw,R);
    double optCost = costAttack(data.insts,R);
    double mthCost = costAttackParallel(datam.insts,datam.count,datam.p,R);
    double rprCost = costAttackParallel(datap.instsRaw,datap.count,datap.p,R);
    double parCost = costAttackParallel(datap.insts,datap.count,datap.p,R);
    double stdCost = standardCost(datap.ll,datap.mem,datap.iters,R);
    double monCost = standardCostMono(data.mem,data.iters,R);
    ans.rawVsStd = stdCost/rawCost;
    ans.rawVsMon = monCost/rawCost;
    ans.optVsStd = stdCost/optCost;
    ans.optVsMon = monCost/optCost;
    ans.mthVsStd = stdCost/mthCost;
    ans.mthVsMon = monCost/mthCost;
    ans.rprVsStd = stdCost/rprCost;
    ans.rprVsMon = monCost/rprCost;
    ans.parVsStd = stdCost/parCost;
    ans.parVsMon = monCost/parCost;
    return ans;
}

AttackQuickStat attackFastStat(size_t p, size_t mem, uint32_t iters, double R)
{
    AttackQuickStat ans;
    size_t n = mem*iters;
    Graph G = (Graph)malloc(sizeof(Node)*(n-2*p));
    genGraph(p,iters,mem,G);
    ans.npar = searchForParameters(G,n,iters,R,p,false,false);
    size_t layers[ans.npar.lay], *segments[ans.npar.lay];
    for(size_t ly = 0; ly < ans.npar.lay; ly++)
    {
        segments[ly] = (size_t*)malloc(sizeof(size_t)*(ans.npar.seg+1));
    }
    getLayers(ans.npar.lay,n/p,layers);
    LGraph H = (LGraph)malloc(sizeof(Node)*(n));
    linGraph(G,layers,p,mem,n,H);
    morphLayers(p,ans.npar.lay,layers);
    getSegments(ans.npar.seg,ans.npar.lay,layers,segments);
    setLayers(H,n,layers);
    setSegments(H,n,segments);
    Set S = (Set)malloc(n);
    selectS(H,n,S);
    expandS(S,n,p,ans.npar.lay,layers);
    double nprCost = costAttackEst(H,n,iters,S,ans.npar.lay,ans.npar.seg,layers,segments,ans.npar.g,R,false);
    for(size_t ly = 0; ly < ans.npar.lay; ly++)
    {
        free(segments[ly]);
    }
    ans.para = searchForParameters(G,n,iters,R,p,false,true);
    size_t layersp[ans.para.lay], *segmentsp[ans.para.lay];
    for(size_t ly = 0; ly < ans.para.lay; ly++)
    {
        segmentsp[ly] = (size_t*)malloc(sizeof(size_t)*(ans.para.seg+1));
    }
    getLayers(ans.para.lay,n/p,layersp);
    linGraph(G,layersp,p,mem,n,H);
    free(G);
    morphLayers(p,ans.para.lay,layersp);
    getSegments(ans.para.seg,ans.para.lay,layersp,segmentsp);
    setLayers(H,n,layersp);
    setSegments(H,n,segmentsp);
    selectS(H,n,S);
    expandS(S,n,p,ans.para.lay,layersp);
    double parCost = costAttackEst(H,n,iters,S,ans.para.lay,ans.para.seg,layersp,segmentsp,ans.para.g,R,true);
    free(H);
    free(S);
    for(size_t ly = 0; ly < ans.para.lay; ly++)
    {
        free(segmentsp[ly]);
    }
    double stdCost = standardCost(p,mem,iters,R);
    double monCost = standardCostMono(mem,iters,R);
    ans.nprVsStd = stdCost/nprCost;
    ans.nprVsMon = monCost/nprCost;
    ans.parVsStd = stdCost/parCost;
    ans.parVsMon = monCost/parCost;
    return ans;
}

void attackRun(AttackData data, const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, void* out, size_t outlen)
{
    size_t t1 = 28+pwdlen;
    size_t t2 = 32+pwdlen+saltlen;
    uint8_t init[t2+8];
    memcpy(init,&(data.ll),4);
    memcpy(init+4,&outlen,4);
    memcpy(init+8,&(data.mem),4);
    memcpy(init+12,&(data.iters),4);
    memset(init+16,0x13,1);
    memset(init+17,0,3);
    memset(init+20,1,1);
    memset(init+21,0,3);
    memcpy(init+24,&pwdlen,4);
    memcpy(init+28,pwd,pwdlen);
    memcpy(init+t1,&saltlen,4);
    memcpy(init+t1+4,salt,saltlen);
    memset(init+t2,0,8);
    SuperLong H0;
    blake2bXto64(init,H0,t2+8);
    runAttack(H0,data.insts,out,outlen,data.ll,data.count,data.carret);
}

void attackRunParallel(AttackDataParallel data, const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, void* out, size_t outlen)
{
    size_t t1 = 28+pwdlen;
    size_t t2 = 32+pwdlen+saltlen;
    uint8_t init[t2+8];
    memcpy(init,&(data.ll),4);
    memcpy(init+4,&outlen,4);
    memcpy(init+8,&(data.mem),4);
    memcpy(init+12,&(data.iters),4);
    memset(init+16,0x13,1);
    memset(init+17,0,3);
    memset(init+20,1,1);
    memset(init+21,0,3);
    memcpy(init+24,&pwdlen,4);
    memcpy(init+28,pwd,pwdlen);
    memcpy(init+t1,&saltlen,4);
    memcpy(init+t1+4,salt,saltlen);
    memset(init+t2,0,8);
    SuperLong H0;
    blake2bXto64(init,H0,t2+8);
    runAttackParallel(H0,data.insts,out,outlen,data.ll,data.count,data.carret,data.p);
}

void attackClean(AttackData data)
{
    freeInsts(data.insts);
    freeInsts(data.instsForPara);
    freeInsts(data.instsRaw);
    free(*(data.graph));
    free(data.graph);
}

void attackCleanParallel(AttackDataParallel data)
{
    for(size_t i = 0; i < data.p; i++)
    {
        freeInsts(data.insts[i]);
    }
    free(data.insts);
    if(data.instsRaw)
    {
        for(size_t i = 0; i < data.p; i++)
        {
            freeInsts(data.instsRaw[i]);
        }
        free(data.instsRaw);
    }
}

double attackCost(AttackData data, double R)
{
    return costAttack(data.insts,R);
}

double attackCostParallel(AttackDataParallel data, double R)
{
    return costAttackParallel(data.insts,data.count,data.p,R);
}

double standardCost(size_t p, size_t mem, uint32_t iters, double R)
{
    return mem*(iters*R+(iters-0.5)*(mem/p));
}

double standardCostMono(size_t mem, uint32_t iters, double R)
{
    return mem*(iters*R+(iters-0.5)*mem);
}
