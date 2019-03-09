#ifndef COMMON_H
#define COMMON_H

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Rotate 64-bit value left by specified amount.
#define ROTL64(n, qword) ((qword) << (n) | (qword) >> (64 - (n)))

// Take minimum of two arguments.
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#endif
