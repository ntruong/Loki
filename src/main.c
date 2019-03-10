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

void printhash(unsigned char* D)
{
  for (size_t i = 0; i < 64; ++i) {
    unsigned char x = D[i];
    // Ignore the top bits that would unevenly divide the charmap.
    if (x < (0xff / CHARMAPSIZE * CHARMAPSIZE)) {
      printf("%c", charmap[x % CHARMAPSIZE]);
    }
  }
  printf("\n");
}

// Test SHA3-512 hash.
int test_sha3_512(void)
{
  const char* M     = "accountpass";
  uint64_t* D       = (uint64_t*)SHA3(512, M);
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
    if (D[i] != test[i]) {
      fprintf(stderr, "something went wrong on %ld\n", i);
      fprintf(stderr, "saw:      0x%016llx\n", D[i]);
      fprintf(stderr, "expected: 0x%016llx\n", test[i]);
      return 1;
    }
  }
  printf("we're okay\n");
  return 0;
}

// Help menu stuff.
void help(void)
{
  printf(
    "Usage: loki [options] input [inputs ...]\n"
    "\n"
    "  Generate a hash using the given algorithm with the given inputs.\n"
    "\n"
    "  If no inputs are given, read at most 200 characters from stdin.\n"
    "\n"
    "  If no algorithm is specified, SHA3-512 is used by default.\n"
    "\n"
    "  If multiple options are given, the last specified is used.\n"
    "\n"
    "Options:\n"
    "  --help      display this help and exit\n"
    "  --test      test the output of the selected algorithm\n"
    "  --sha3-512  use SHA3-512\n"
    "\n"
    );
}

typedef enum Flag {
  SHA3_512
} Flag;

int main(int argc, char* argv[])
{
  // Store the last selected algorithm.
  Flag option = SHA3_512;

  // Store the message to hash.
  char* M = NULL;
  size_t Msz = 0;

  // Parse args. Skip over the first argument (should be "loki").
  int test = 0;
  for (size_t i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--help") == 0) {
      help();
      return 0;
    }
    else if (strcmp(argv[i], "--test") == 0) {
      test = 1;
    }
    else if (strcmp(argv[i], "--sha3-512") == 0) {
      option = SHA3_512;
    }
    else {
      M = realloc(M, Msz + strlen(argv[i]) + 1);
      // Haha error checking.
      if (M == NULL) {
        fprintf(stderr, "Could not allocate memory for input message.\n");
        return 1;
      }
      Msz += strlen(argv[i]);
      strcat(M, argv[i]);
      M[Msz] = 0;
    }
  }

  // Check to see if we should test hashes.
  if (test) {
    switch (option) {
      case SHA3_512:
        return test_sha3_512();
      default:
        return test_sha3_512();
    }
  }

  // Check to make sure inputs were given; otherwise, read from stdin.
  if (Msz == 0) {
    M = malloc(200);
    // Haha error checking.
    if (M == NULL) {
      fprintf(stderr, "Could not allocate memory for input message.\n");
      return 1;
    }
    M = fgets(M, 200, stdin);
    if (M == NULL) {
      fprintf(stderr, "Could not read inputs from stdin.\n");
      return 1;
    }
  }

  // Do the hash!
  unsigned char* D;
  switch (option) {
    case SHA3_512:
      D = (unsigned char*)SHA3(512, M);
      break;
    default:
      D = (unsigned char*)SHA3(512, M);
      break;
  }
  printhash(D);
  free(D);

  return 0;
}
