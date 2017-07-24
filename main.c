#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "argon2/argon2i.h"
#include "attack/attack.h"


int main(int argc, char *argv[])
{
    size_t pwdlen, saltlen, outlen, p, mem;
    uint32_t iters;
    double R;
    if(argc != 8)
    {
        printf("Error! Incorrect argument count!\nCorrect usage:\nattack <password length> <salt length> <hash length> <R> <#lanes> <#memory blocks (KiB)> <#passes>\n");
        exit(EXIT_FAILURE);
    }
    sscanf(argv[1],"%zu",&pwdlen);
    sscanf(argv[2],"%zu",&saltlen);
    sscanf(argv[3],"%zu",&outlen);
    sscanf(argv[4],"%lf",&R);
    sscanf(argv[5],"%zu",&p);
    sscanf(argv[6],"%zu",&mem);
    sscanf(argv[7],"%u",&iters);
    printf("Password length: %zu - Salt length: %zu - Hash length: %zu\n",pwdlen,saltlen,outlen);
    printf("Parallelism: %zu - Memory space: %zu - Iterations: %u\n",p,mem,iters);
    printf("Energy cost ratio: %.2lf\n\n\n",R);
    clock_t stat, std, prep, prepm, prepp, run, multi, para;
    stat = clock();
    AttackQuickStat qst = attackFastStat(p,mem,iters,R);
    stat = clock() - stat;
    printf("Attack quality:\n              Non-Parallel Parallel\nVs Standard     %8.4lf  %8.4lf\nVs Monothreaded %8.4lf  %8.4lf\n\n",qst.nprVsStd,qst.parVsStd,qst.nprVsMon,qst.parVsMon);
    printf("Attack quality estimated in %.3lf seconds\n\n",((double)stat)/CLOCKS_PER_SEC);
    printf("Choosen parameters:\n         Non-Parallel Parallel\nLayers     %8zu   %8zu\nSegments   %8zu   %8zu\ng          %8u   %8u\nd          %8u   %8u\n\n\n",qst.npar.lay,qst.para.lay,qst.npar.seg,qst.para.seg,qst.npar.g,qst.para.g,qst.npar.d,qst.para.d);
    uint8_t pwd[pwdlen], salt[saltlen], outS[outlen], outA[outlen], outM[outlen], outP[outlen];
    srand(time(NULL));
    for(size_t i = 0; i < pwdlen; i++)
    {
        pwd[i] = rand();
    }
    for(size_t i = 0; i < saltlen; i++)
    {
        salt[i] = rand();
    }
    uint64_t pwd64=0, salt64=0, outS64=0, outA64=0, outM64=0, outP64=0;
    for(size_t i = 0; i < pwdlen; i++)
    {
        uint64_t tmp = pwd[i];
        tmp<<= 8*(i%8);
        pwd64^= tmp;
    }
    for(size_t i = 0; i < saltlen; i++)
    {
        uint64_t tmp = salt[i];
        tmp<<= 8*(i%8);
        salt64^= tmp;
    }
    int pwdpr = (2*pwdlen>=16)?16:2*pwdlen;
    int saltpr = (2*saltlen>=16)?16:2*saltlen;
    printf("Pasword %.*lX - Salt %.*lX\n\n",pwdpr,pwd64,saltpr,salt64);
    std = clock();
    argon2i(p,mem,iters,pwd,pwdlen,salt,saltlen,outS,outlen);
    std = clock() - std;
    for(size_t i = 0; i < outlen; i++)
    {
        uint64_t tmp = outS[i];
        tmp<<= 8*(i%8);
        outS64^= tmp;
    }
    int outpr = (2*outlen>=16)?16:2*outlen;
    printf("Hashed to %.*lX using standard Argon2i v1.3\n",outpr,outS64);
    prep = clock();
    AttackData attack = attackPrep(p,mem,iters,R);
    prep = clock() - prep;
    run = clock();
    attackRun(attack,pwd,pwdlen,salt,saltlen,outA,outlen);
    run = clock() - run;
    for(size_t i = 0; i < outlen; i++)
    {
        uint64_t tmp = outA[i];
        tmp<<= 8*(i%8);
        outA64^= tmp;
    }
    printf("Hashed to %.*lX using attack against Argon2i v1.3\n",outpr,outA64);
    prepm = clock();
    AttackDataParallel attackm = attackParallelize(attack,R);
    prepm = clock() - prepm;
    multi = clock();
    attackRunParallel(attackm,pwd,pwdlen,salt,saltlen,outM,outlen);
    multi = clock() - multi;
    for(size_t i = 0; i < outlen; i++)
    {
        uint64_t tmp = outM[i];
        tmp<<= 8*(i%8);
        outM64^= tmp;
    }
    printf("Hashed to %.*lX using multithreaded attack against Argon2i v1.3\n",outpr,outM64);
    prepp = clock();
    AttackDataParallel attackp = attackPrepParallel(p,mem,iters,R);
    prepp = clock() - prepp;
    AttackStat st = attackGetStat(attack,attackm,attackp,R);
    attackClean(attack);
    attackCleanParallel(attackm);
    para = clock();
    attackRunParallel(attackp,pwd,pwdlen,salt,saltlen,outP,outlen);
    para = clock() - para;
    attackCleanParallel(attackp);
    for(size_t i = 0; i < outlen; i++)
    {
        uint64_t tmp = outP[i];
        tmp<<= 8*(i%8);
        outP64^= tmp;
    }
    printf("Hashed to %.*lX using parallel attack against Argon2i v1.3\n\n\n",outpr,outP64);
    printf("Attack quality:\n                   Raw   Optimized Multithreaded Raw-Parallel Parallel\nVs Standard     %8.4lf  %8.4lf    %8.4lf     %8.4lf   %8.4lf\nVs Monothreaded %8.4lf  %8.4lf    %8.4lf     %8.4lf   %8.4lf\n\n",st.rawVsStd,st.optVsStd,st.mthVsStd,st.rprVsStd,st.parVsStd,st.rawVsMon,st.optVsMon,st.mthVsMon,st.rprVsMon,st.parVsMon);
    printf("Calculation times (seconds):\n              Precalculation    Run\nStandard            -        %8.3lf\nMonothreaded    %8.3lf     %8.3lf\nMultithreaded   %8.3lf     %8.3lf\nParallel        %8.3lf     %8.3lf\n\n",((double)std)/CLOCKS_PER_SEC,((double)prep)/CLOCKS_PER_SEC,((double)run)/CLOCKS_PER_SEC,((double)prep+prepm)/CLOCKS_PER_SEC,((double)multi)/CLOCKS_PER_SEC,((double)prepp)/CLOCKS_PER_SEC,((double)para)/CLOCKS_PER_SEC);
    printf("Used parameters:\n         Non-Parallel Parallel\nLayers     %8zu   %8zu\nSegments   %8zu   %8zu\ng          %8u   %8u\nd          %8u   %8u\n",attack.prm.lay,attackp.prm.lay,attack.prm.seg,attackp.prm.seg,attack.prm.g,attackp.prm.g,attack.prm.d,attackp.prm.d);
    return EXIT_SUCCESS;
}
