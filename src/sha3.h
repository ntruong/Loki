#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stdlib.h>

// SHA-3 constants.
#define WIDTH        1600
#define PERMUTATIONS 25
#define ROUNDS       25

// SHA-3 state.
typedef struct sha3state {
  uint64_t A[PERMUTATIONS];
  size_t   N;
} sha3state;

// Keccak-p steps.
void theta(uint64_t* A);
void rho(uint64_t* A);
void pi(uint64_t* A);
void chi(uint64_t* A);
void iota(uint64_t* A, size_t round_index);

enum {
  _B    = 1600,
  _W    = 64,
  _L    = 6
};

// Rotate 64-bit value left by specified amount.
#define ROTL64(n, qword) ((qword) << (n) | (qword) >> (64 - (n)))

// XOR every fifth 64-bit value in the state.
#define XOR(A, i) ( \
  A[(i)     ] ^ \
  A[(i) +  5] ^ \
  A[(i) + 10] ^ \
  A[(i) + 15] ^ \
  A[(i) + 20]   \
  )

#endif
