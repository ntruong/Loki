#include "common.h"
#include "sha3.h"

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
