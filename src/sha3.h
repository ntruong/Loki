#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stdlib.h>

// SHA-3 constants.
#define WIDTH        1600
#define PERMUTATIONS 25
#define ROUNDS       24

static const uint64_t RC[ROUNDS] = {
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

// Keccak-p steps.
void theta(uint64_t* A);
void rho(uint64_t* A);
void pi(uint64_t* A);
void chi(uint64_t* A);
void iota(uint64_t* A, size_t ir);
void keccakf(uint64_t* A);

// Sponge construction.
void process(void (*f)(uint64_t*), uint64_t* S, uint64_t* P, size_t r);
void pad(char* P, size_t, size_t);
void* sponge(
  void (*f)(uint64_t*),
  void (*p)(char*, size_t, size_t),
  size_t r,
  const char* N,
  size_t d
);

// Create SHA3 function.
#define KECCAK(c, N, d) sponge(&keccakf, &pad, WIDTH - (c), (N), (d))
#define SHA3(N, M) KECCAK((N) * 2, M, (N))

// XOR every fifth 64-bit value in the state.
#define XOR(A, i) ( \
  A[(i)     ] ^ \
  A[(i) +  5] ^ \
  A[(i) + 10] ^ \
  A[(i) + 15] ^ \
  A[(i) + 20]   \
  )

#endif
