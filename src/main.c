#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Constants go here.
enum {
  _B    = 1600,
  _W    = 64,
  _L    = 6
};

// Rotate a given bitstring left by the specified amount.
uint64_t rot(size_t bits, uint64_t x)
{
  return (x << bits) | (x >> (64 - bits));
}

// Step one of Keccak-p.
uint64_t* theta(uint64_t* words)
{
  uint64_t C[5] = {0};
  uint64_t D[5] = {0};

  // For all pairs ... let C[x, z] = ^ A[x, _, z].
  for (size_t idx = 0; idx < _B / _W; ++idx) {
    C[idx % 5] ^= words[idx];
  }

  // For all pairs ... let D[x, z] = C[x - 1, z] ^ C[x + 1, z - 1].
  for (size_t idx = 0; idx < 5; ++idx) {
    D[idx] = C[(idx + 4) % 5] ^ rot(1, C[(idx + 1) % 5]);
  }

  // For all triples ... let A'[x, y, z] = A[x, y, z] ^ D[x, z].
  for (size_t idx = 0; idx < _B / _W; ++idx) {
    words[idx] ^= D[idx % 5];
  }

  return words;
}

// Step two of Keccak-p.
uint64_t* rho(uint64_t* words)
{
  uint64_t words_[25];

  // For all z ... let A'[0, 0, z] = A[0, 0, z].
  words_[0] = words[0];

  size_t x = 1;
  size_t old_x;
  size_t y = 0;
  size_t offset;
  for (size_t t = 0; t < 24; ++t) {
    // For all z ... let A'[x, y, z] = A[x, y, z - (t + 1)(t + 2)/2].
    offset = ((t + 1) * (t + 2) / 2) % _W;
    words_[5 * y + x] = rot(offset, words[5 * y + x]);
    old_x = x;
    x = y;
    y = (2 * old_x + 3 * y) % 5;
  }

  // Move A' to A.
  memcpy(words, words_, _B / 8);
  return words;
}

// Step three of Keccak-p.
uint64_t* pi(uint64_t* words)
{
  uint64_t words_[25];

  // For all triples ... let A'[x, y, z] = A[x + 3y, x, z].
  for (size_t y = 0; y < 5; ++y) {
    for (size_t x = 0; x < 5; ++x) {
      words_[5 * y + x] = words[5 * x + ((x + 3 * y) % 5)];
    }
  }

  // Move A' to A.
  memcpy(words, words_, _B / 8);
  return words;
}

// Step four of Keccak-p.
uint64_t* chi(uint64_t* words)
{
  uint64_t words_[25];
  uint64_t others = 0;

  // For all triples ... let
  // A'[x, y, z] = A[x, y, z] ^ (!A[x + 1, y, z] & A[x + 2, y, z]).
  for (size_t y = 0; y < 5; ++y) {
    for (size_t x = 0; x < 5; ++x) {
      others = words[5 * y + ((x + 1) % 5)] & words[5 * y + ((x + 2) % 5)];
      words_[5 * y + x] = words[5 * y + x] ^ others;
    }
  }

  // Move A' to A.
  memcpy(words, words_, _B / 8);
  return words;
}

// Step five of Keccak-p.
uint8_t rc(uint8_t t)
{
  // If t mod 255 = 0, return 1.
  if (t == 0) {
    return 1;
  }

  uint8_t R  = 0x80;
  uint8_t R0;
  uint8_t R4;
  uint8_t R5;
  uint8_t R6;
  uint8_t R8;
  // For i from 1 to t mod 255, let ...
  //     0   1   2   3   4   5   6   7   8
  // R = 0 | _ | _ | _ | _ | _ | _ | _ | _
  //        x80 x40 x20 x10 x08 x04 x02 x01
  for (size_t idx = 0; idx <= t; ++idx) {
    R4 = (0x10 & R) >> 4;
    R5 = (0x08 & R) >> 3;
    R6 = (0x04 & R) >> 2;
    R8 = (0x01 & R);
    // R[0] = R[0] ^ R[8].
    R0 = (0 ^ R8) << 7;
    // R[4] = R[4] ^ R[8].
    R4 = (R4 ^ R8) << 3;
    // R[5] = R[5] ^ R[8].
    R5 = (R5 ^ R8) << 2;
    // R[6] = R[6] ^ R[8].
    R6 = (R6 ^ R8) << 1;
    // R = Trunc8[R].
    R = R0 | R4 | R5 | R6 | ((R >> 1) & 0b01110001);
  }

  // Return R[0].
  return R >> 7;
}

uint64_t* iota(uint64_t* words, uint64_t ir)
{
  uint64_t RC = 0;

  // For j from 0 to l, let RC[2^j - 1] = rc(j + 7ir).
  for (size_t j = 0; j <= _L; ++j) {
    RC |= rc(j + 7 * ir) << (64 - (1 << j));
  }

  // For all z ... let A'[0, 0, z] = A'[0, 0, z] ^ RC[z].
  words[0] ^= RC;
  return words;
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
  uint64_t S[_B / 8];
  char Pi[_B / 8];
  memset(S,  0, _B / 8);
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
  printf("%s\n", resp);

  free(Mbase);
  free(resp);
  return 0;
}
