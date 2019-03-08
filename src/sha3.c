#include "sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Character map so we don't have to worry about encoding.
#define CHARMAPSIZE 85
static const unsigned char charmap[CHARMAPSIZE] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', '0', '1', '2', '3', '4', '!',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
  'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
  'y', 'z', '5', '6', '7', '8', '9', '@',
  '#', '$', '%', '^', '&', '*', '(', ')',
  '~', '-', '_', '=', '+', '[', ']', '/',
  '?', ';', ':', ',', '.'
};

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
void chi(uint64_t* A)
{
  // For all triples ... let
  // A'[x, y, z] = A[x, y, z] ^ (~A[x + 1, y, z] & A[x + 2, y, z]).
  uint64_t A0, A1;
  for (size_t i = 0; i < PERMUTATIONS; i += 5) {
    A0 = A[i];
    A1 = A[i + 1];
    A[i    ] = A0       ^ (~A1       & A[i + 2]);
    A[i + 1] = A1       ^ (~A[i + 2] & A[i + 3]);
    A[i + 2] = A[i + 2] ^ (~A[i + 3] & A[i + 4]);
    A[i + 3] = A[i + 3] ^ (~A[i + 4] & A0);
    A[i + 4] = A[i + 4] ^ (~A0       & A1);
  }
}

// Step five of Keccak-p.
void iota(uint64_t* A, size_t ir)
{
  // For all z ... let A'[0, 0, z] = A'[0, 0, z] ^ RC[z].
  A[0] ^= RC[ir];
}

// Keccak-f[1600] corresponding to Keccak-p[1600, 24].
void keccakf(uint64_t* A)
{
  for (size_t ir = 0; ir < ROUNDS; ++ir) {
    theta(A);
    rho(A);
    pi(A);
    chi(A);
    iota(A, ir);
  }
}

// Sponge construction.
void process(void (*f)(uint64_t*), uint64_t* S, uint64_t* P, size_t r) {
  for (size_t i = 0; i < r / sizeof(uint64_t); ++i) {
    S[i] ^= P[i];
  }
  f(S);
}

void pad(char* P, size_t sz, size_t r)
{
  P[sz]    = 0x06;
  P[r - 1] = 0x80;
}

void* sponge(
  void (*f)(uint64_t*),
  void (*p)(char*, size_t, size_t),
  size_t r,
  const char* N,
  size_t d
)
{
  // Turn bits to bytes because it's easier.
  r >>= 3;
  d >>= 3;

  // Current hash state.
  uint64_t S[PERMUTATIONS] = {0};

  // Take whole r-bit blocks from the message N until we have to pad.
  size_t Nsz = strlen(N);
  while (Nsz >= r) {
    process(f, S, (uint64_t*)N, r);
    Nsz -= r;
    N   += r;
  }
  // We have to pad now; N || 0x06 || ... || 0x80.
  uint64_t P[PERMUTATIONS] = {0};
  memcpy(P, N, Nsz);
  p((char*)P, Nsz, r);
  process(f, S, (uint64_t*)P, r);

  // Prepare d-bit string to return.
  void* Z = (char*)malloc(d);
  size_t Zoff = MIN(d, r);
  memset(Z, 0, d);
  memcpy(Z, S, Zoff);
  size_t Zsz = Zoff;
  while (Zsz < d) {
    f(S);
    Zoff = MIN(d - Zsz, r);
    memcpy(Z + Zsz, S, Zoff);
    Zsz += Zoff;
  }

  return Z;
}

int main(int argc, char* argv[])
{
  // Test to see if the hash is correct (endian problems?).
  if (argc == 2 && strcmp(argv[1], "--test") == 0) {
    const char* M = "accountpass";
    uint64_t* resp    = (uint64_t*)SHA3(512, M);
    uint64_t  test[8] = {
      0x030650435daf108b,
      0x590d142c651e113a,
      0xcab3774575774745,
      0x1d4b1e3ea10bd6d9,
      0x010f069faec9d42e,
      0xdb7f5ed5b89bb94e,
      0xa70c9ecb9a77c0c8,
      0x2d5391b13744af4f
    };
    for (size_t i = 0; i < 512 / 8 / sizeof(uint64_t); ++i) {
      if (resp[i] != test[i]) {
        fprintf(stderr, "something went wrong on %ld\n", i);
        fprintf(stderr, "saw:      0x%016llx\n", resp[i]);
        fprintf(stderr, "expected: 0x%016llx\n", test[i]);
        return 1;
      }
    }
    printf("we're okay\n");
    return 0;
  }

  // Check for enough inputs
  if (argc != 3) {
    fprintf(stderr, "usage: loki [account] [password]\n");
    return 1;
  }

  // Join the two input strings.
  char M[strlen(argv[1]) + strlen(argv[2])];
  strcpy(M, argv[1]);
  strcat(M, argv[2]);

  unsigned char* resp = (unsigned char*)SHA3(512, M);
  for (size_t i = 0; i < 64; ++i) {
    unsigned char x = resp[i];
    // Ignore the top bits that would unevenly divide the charmap.
    if (x < (0xff / CHARMAPSIZE * CHARMAPSIZE)) {
      printf("%c", charmap[x % CHARMAPSIZE]);
    }
  }
  printf("\n");
  free(resp);

  return 0;
}
