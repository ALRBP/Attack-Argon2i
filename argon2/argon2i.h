#include <stddef.h>
#include <stdint.h>

#define ARGON2I_SUPER_LONG_SIZE 64
#define ARGON2I_QWORDS_IN_SUPER_LONG ARGON2I_SUPER_LONG_SIZE/8


typedef uint64_t SuperLong[ARGON2I_QWORDS_IN_SUPER_LONG];


void argon2i(size_t p, size_t mem, uint32_t iters, const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, void* out, size_t outlen);
