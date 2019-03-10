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
  while (*D) {
    unsigned char x = *D++;
    // Ignore the top bits that would unevenly divide the charmap.
    if (x < (0xff / CHARMAPSIZE * CHARMAPSIZE)) {
      printf("%c", charmap[x % CHARMAPSIZE]);
    }
  }
  printf("\n");
}

// Test string.
static const char* testM = "password";

// Test messages.
int test_output(uint64_t* msg, uint64_t* key, size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    if (msg[i] != key[i]) {
      fprintf(stderr, "something went wrong on %ld\n", i);
      fprintf(stderr, "saw:      0x%016llx\n", msg[i]);
      fprintf(stderr, "expected: 0x%016llx\n", key[i]);
      return 1;
    }
  }
  printf("we're okay\n");
  return 0;
}

// Test SHA3-256 hash.
int test_sha3_256(void)
{
  uint64_t* msg    = (uint64_t*)SHA3(256, testM);
  uint64_t  key[4] = {
    0x007fe8f44a7d06c0,
    0x23286815b663acdb,
    0x67acbe1b2d175970,
    0x84a4fda9d6457342
  };
  return test_output(msg, key, 4);
}

// Test SHA3-512 hash.
int test_sha3_512(void)
{
  uint64_t* msg    = (uint64_t*)SHA3(512, testM);
  uint64_t  key[8] = {
    0x0a556a738654a7e9,
    0x058337e261a8fef4,
    0xe1de9450a055a5c4,
    0xc39ca4fe8af6a2dc,
    0xa51e13eae68d0ea5,
    0xa154b06f4d1f3121,
    0x2eff358e2f28e846,
    0x1697902ea6c16863
  };
  return test_output(msg, key, 8);
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
  SHA3_256,
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
    else if (strcmp(argv[i], "--sha3-256") == 0) {
      option = SHA3_256;
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
      case SHA3_256:
        return test_sha3_256();
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
    case SHA3_256:
      D = (unsigned char*)SHA3(256, M);
      break;
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
