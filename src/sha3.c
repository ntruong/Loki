#include "sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Step one of Keccak-p.
void theta(uint64_t* A)
{
  // For all pairs ... let D[x, z] = C[x - 1, z] ^ C[x + 1, z - 1].
  uint64_t D[5] = {
    XOR(A, 4) ^ ROTL64(1, XOR(A, 1)),
    XOR(A, 0) ^ ROTL64(1, XOR(A, 2)),
    XOR(A, 1) ^ ROTL64(1, XOR(A, 3)),
    XOR(A, 2) ^ ROTL64(1, XOR(A, 4)),
    XOR(A, 3) ^ ROTL64(1, XOR(A, 0)),
  };

  // For all triples ... let A'[x, y, z] = A[x, y, z] ^ D[x, z].
  for (size_t i = 0; i < PERMUTATIONS; ++i) {
    A[i] ^= D[i % 5];
  }
}

// Step two of Keccak-p.
void rho(uint64_t* A)
{
  // For all z ... let A'[x, y, z] = A[x, y, z - (t + 1)(t + 2)/2].
  A[ 1] = ROTL64( 1, A[ 1]);
  A[ 2] = ROTL64(62, A[ 2]);
  A[ 3] = ROTL64(28, A[ 3]);
  A[ 4] = ROTL64(27, A[ 4]);
  A[ 5] = ROTL64(36, A[ 5]);
  A[ 6] = ROTL64(44, A[ 6]);
  A[ 7] = ROTL64( 6, A[ 7]);
  A[ 8] = ROTL64(55, A[ 8]);
  A[ 9] = ROTL64(20, A[ 9]);
  A[10] = ROTL64( 3, A[10]);
  A[11] = ROTL64(10, A[11]);
  A[12] = ROTL64(43, A[12]);
  A[13] = ROTL64(25, A[13]);
  A[14] = ROTL64(39, A[14]);
  A[15] = ROTL64(41, A[15]);
  A[16] = ROTL64(45, A[16]);
  A[17] = ROTL64(15, A[17]);
  A[18] = ROTL64(21, A[18]);
  A[19] = ROTL64( 8, A[19]);
  A[20] = ROTL64(18, A[20]);
  A[21] = ROTL64( 2, A[21]);
  A[22] = ROTL64(61, A[22]);
  A[23] = ROTL64(56, A[23]);
  A[24] = ROTL64(14, A[24]);
}

// Step three of Keccak-p.
void pi(uint64_t* A)
{
  // Save some point before rearrangement; we choose A[1, 0].
  uint64_t A1 = A[1];

  // For all triples ... let A'[x, y, z] = A[x + 3y, x, z].
  // Then we see A[5y + x] = A[6x + 3y (mod 5)] and write
  A[ 1] = A[ 6];
  A[ 6] = A[ 9];
  A[ 9] = A[22];
  A[22] = A[14];
  A[14] = A[20];
  A[20] = A[ 2];
  A[ 2] = A[12];
  A[12] = A[13];
  A[13] = A[19];
  A[19] = A[23];
  A[23] = A[15];
  A[15] = A[ 4];
  A[ 4] = A[24];
  A[24] = A[21];
  A[21] = A[ 8];
  A[ 8] = A[16];
  A[16] = A[ 5];
  A[ 5] = A[ 3];
  A[ 3] = A[18];
  A[18] = A[17];
  A[17] = A[11];
  A[11] = A[ 7];
  A[ 7] = A[10];
  A[10] = A1;
}

// Step four of Keccak-p.
void chi(uint64_t* words)
{
  uint64_t words_[25];
  uint64_t others = 0;

  // For all triples ... let
  // A'[x, y, z] = A[x, y, z] ^ (~A[x + 1, y, z] & A[x + 2, y, z]).
  for (size_t y = 0; y < 5; ++y) {
    for (size_t x = 0; x < 5; ++x) {
      others = ~words[5 * y + ((x + 1) % 5)] & words[5 * y + ((x + 2) % 5)];
      words_[5 * y + x] = words[5 * y + x] ^ others;
    }
  }

  // Move A' to A.
  memcpy(words, words_, _B / 8);
}

// Step five of Keccak-p.
uint64_t rc(uint64_t t)
{
  uint64_t R = 0x1;
  // For i from 1 to t mod 255, let ...
  for (size_t idx = 1; idx <= t; ++idx) {
    R <<= 1;
    if (R & 0x100) {
      R ^= 0x71;
    }
  }

  // Return R[0].
  return R & 0x1;
}

void iota(uint64_t* words, size_t ir)
{
  uint64_t RC = 0;

  // For j from 0 to l, let RC[2^j - 1] = rc(j + 7ir).
  for (size_t j = 0; j <= _L; ++j) {
    RC |= rc(j + 7 * ir) << ((1 << j) - 1);
  }

  // For all z ... let A'[0, 0, z] = A'[0, 0, z] ^ RC[z].
  words[0] ^= RC;
}

// Keccak-f[1600] corresponding to Keccak-p[1600, 24].
uint64_t* keccakf(uint64_t* S)
{
  for (size_t ir = 12 + 2 * _L - 24; ir < 12 + 2 * _L; ++ir) {
    theta(S);
    rho(S);
    pi(S);
    chi(S);
    iota(S, ir);
  }
  return S;
}

// XOR the given blocks of memory for the given number of bytes.
void* memxor(void* restrict dst, const void* restrict src, size_t n)
{
  void* dst_ = dst;
  while (n-- > 0) {
    *(char*)dst++ ^= *(char*)src++;
  }
  return dst_;
}

// Pad10*1.
typedef struct {
  char* P;
  size_t n;
} padded;

padded* pad(int64_t x, int64_t m)
{
  padded* result = malloc(sizeof(padded));
  size_t j = ((-m - 2) % x + x) % x;
  // Total byte size of the padded string.
  result->n = (m + j + 2) / 8;
  char* P = (char*)malloc(result->n);
  memset(P, 0, result->n);
  // Clear the first m bits, setting the next bit to 1.
  P[m / 8] = 0x80 >> (m % 8);
  P[result->n - 1] = 0x01;
  result->P = P;
  return result;
}

// Sponge.
char* sponge(
  uint64_t* (*f)(uint64_t*),
  padded* (*pad)(int64_t, int64_t),
  size_t r,
  char* N,
  size_t d
)
{
  // Convert r, d to bytes.
  r /= 8;
  d /= 8;
  // let P = N || pad(r, len(N)).
  size_t szN = strlen(N);
  padded* padresult = pad(r * 8, szN * 8);
  char* P = padresult->P;
  memcpy(P, N, szN);
  size_t pidx = 0;
  size_t n = padresult->n / r;
  // Let S = 0^b.
  uint64_t S[_B / _W];
  memset(S,  0, _B / 8);
  char Pi[_B / 8];
  // For i from 0 to n - 1, let S = f(S ^ (Pi || 0^c)).
  for (size_t idx = 0; idx < n; ++idx) {
    memset(Pi, 0, _B / 8);
    memcpy(Pi, &P[pidx++ * r], r);
    memxor(S, Pi, _B / 8);
    f(S);
  }
  // Get d bits.
  char* Z = (char*)malloc(d / 8);
  char* Zbase = Z;
  size_t ceil = (r - 1) / d + 1;
  for (size_t idx = 0; idx < ceil; ++idx) {
    // Only copy the last r % d bytes on the last iteration.
    // If d == r, then we should go ahead and copy all r bytes.
    memcpy(Z, S, idx == ceil - 1 ? (d == r ? r : r % d) : r);
    f(S);
    Z += r / sizeof(uint64_t);
  }
  // Release memory.
  free(P);
  return Zbase;
}

// Kekkak[c].
char* keccak(size_t c, char* N, size_t d)
{
  return sponge(&keccakf, &pad, _B - c, N, d);
}

void test() {
  printf("starting bad\n");
  uint64_t ir = 1;
  uint64_t RC = 0;
  printf("0x%llx\n", RC);

  for (size_t j = 0; j <= _L; ++j) {
    RC |= rc(j + 7 * ir) << ((1 << j) - 1);
    printf(";;;\n");
    printf("rc:  0x%llx\n", rc(j + 7 * ir));
    printf("RC: 0x%016llx\n", RC);
  }
}

int main(int argc, char* argv[])
{
  if (argc != 3) {
    fprintf(stderr, "usage: loki [account] [password]\n");
    return 1;
  }

  char* M = (char*)malloc(strlen(argv[1]) + strlen(argv[2]) + 1);
  char* Mbase = M;
  memcpy(M, argv[1], strlen(argv[1]));
  M += strlen(argv[1]);
  memcpy(M, argv[2], strlen(argv[2]));
  M += strlen(argv[2]);
  *M = 0x01;

  char* resp = keccak(1024, Mbase, 512);
  // printf("%s\n", resp);
  printf("%llx\n", *(uint64_t*)resp);
  /* SHA512("accountpass") ->
   *
   * 8b10af5d435006033a111e652c140d59
   * 454777754577b3cad9d60ba13e1e4b1d
   * 2ed4c9ae9f060f014eb99bb8d55e7fdb
   * c8c0779acb9e0ca74faf4437b191532d
   */

  // test();

  free(Mbase);
  free(resp);
  return 0;
}
