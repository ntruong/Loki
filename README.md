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
also included in the repository.
