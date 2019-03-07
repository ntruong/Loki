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

// Keccak-p.
uint64_t* keccakp(uint64_t* S, uint64_t nr)
{
  for (size_t ir = 12 + 2 * _L - nr; ir < 12 + 2 * _L; ++ir) {
    theta(S);
    rho(S);
    pi(S);
    chi(S);
    iota(S, ir);
  }
  return S;
}

int main(int argc, char* argv[])
{
  if (argc != 3) {
    fprintf(stderr, "usage: loki [account] [password]\n");
    return 1;
  }

  return 0;
}
