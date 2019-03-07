# Loki

```
~$ loki account password
BEADC7B39D1109225147DB81C0F399
```

Loki is a tool that hashes an account with a master password to generate a new
password specific to that account. We concatenate the given account and password
before passing to SHA512 and truncating to 32 characters.

# Implementation
We referenced the 2015
[publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) by NIST,
also included in the repository. Some details are reproduced and/or explained
below.

## State Array and Strings
> Given a bitstring `S`, we define the corresponding state array `A` as
```
A[x, y, z] = S[w(5y + x) + z].
```

## Step Mappings
> The five step mappings that comprise a round of `Keccak-p[b, n]` are denoted
> by `theta`, `rho`, `pi`, `chi`, and `iota`.

### Theta
> 1. For all pairs `(x, z)` ..., let
```
     C[x, z] = A[x, 0, z] ^ A[x, 1, z] ^ A[x, 2, z] ^ A[x, 3, z] ^ A[x, 4, z].
```
> 2. For all pairs `(x, z)` ..., let
```
     D[x, z] = C[(x - 1) mod 5, z] ^ C[(x + 1) mod 5, (z - 1) mod w].
```
> 3. For all triples `(x, y, z)` ..., let
```
     A'[x, y, z] = A[x, y, z] ^ D[x, z].
```

> The effect of theta is to XOR each bit in the state with the parities of two
> columns in the array.

### Rho
> 2. Let `(x, y) = (1, 0)`.
> 3. For `t` from 0 to 23:
>      a. for all z ... let
```
          A'[x, y, z] = A[x, y, (z - (t + 1)(t + 2)/2) mod w].
```
>      b. let `(x, y) = (y, (2x + 3y) mod 5)`.

> The effect of rho is to rotate the bits of each lane by a length, called the
> offset, which depends on the fixed x and y coordinates of the lane.

### Pi
> 1. For all triples ... let
```
     A'[x, y, z] = A[(x + 3y) mod 5, x, z].
```

> The effect of pi is to rearrange the positions of the lanes.

### Chi
> 1. For all triples ... let
```
     A'[x, y, z] = A[x, y, z] ^ (!A[(x + 1) mod 5, y, z] * A[(x + 2) mod 5, y, z]).
```

> The dot in the right side indicates integer multiplication ... equivalent to
> the intended Boolean AND operation.

> The effect of chi is to XOR each bit with a non-linear function of two other
> bits in its row.

### Iota
> 2. Let `RC = 0^w`.
> 3. For `j` from 0 to l, let
```
     RC[2^j - 1] = rc(j + 7ir).
```
> 4. For all z ... let
```
     A'[0, 0, z] = A'[0, 0, z] ^ RC[z].
```

> The effect of iota is to modify some of the bits of lane `(0, 0)` in a manner
> that depends on the round index ir.
