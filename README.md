# Loki

```
~$ loki account password
wQFI^?GD5R4QmUNE*)ca*cJapmL+94=3ok!E_GPB]P(OlJkr4Wc*b-M:/F&xH7,n
```

Loki is a tool that hashes an account with a master password to generate a new
password specific to that account. We concatenate the given account and password
before passing to SHA512 and truncating to 32 characters.

# Implementation
We referenced the 2015
[publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) by NIST,
also included in the repository.

To make sure the hash is correct, run
```
loki --test
```
