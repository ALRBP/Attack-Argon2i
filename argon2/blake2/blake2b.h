#include <stdint.h>

 
void blake2b64to64(const uint64_t in[], uint64_t out[]);
 
void blake2b64toX(const uint64_t in[], uint8_t out[], size_t x);
 
void blake2b76to64(const uint32_t in[], uint64_t out[]);
 
void blake2b1028to64(const uint32_t in[], uint64_t out[]);
 
void blake2b1028toX(const uint32_t in[], uint8_t out[], size_t x);
 
void blake2bXto64(const uint8_t in[], uint64_t out[], size_t x);
