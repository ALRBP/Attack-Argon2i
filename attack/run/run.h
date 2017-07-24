#include "../../argon2/argon2i_a.h"
#include "../inst/inst.h"


void runAttack(SuperLong H0, InstList* insts, void* out, size_t outlen, size_t ll, size_t count, size_t carret);

void runAttackParallel(SuperLong H0, InstList** insts, void* out, size_t outlen, size_t ll, size_t count, size_t carret, size_t p);

double costAttack(InstList* insts, double R);

double costAttackParallel(InstList** insts, size_t count, size_t p, double R);
