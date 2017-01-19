# WardenSigning
Experimenting with Warden signature cracking

I did this to investigate whether there was some vulnerability in the way the WoW client processes the signature on MPQ and Warden files.
I was unable to find such a vulnerability, but I thought this code might be useful to future investigators of the issue.

The verification mode is working, and the repository includes a collection of 72 different sniffed Warden modules and their corresponding
RC4 keys.

Credit for the module archive goes to https://github.com/Neo2003

It requires OpenSSL.

Example output of the module verification mode:

```
Loaded module.  Decompressed size = 30469 bytes.
Signature check PASSED
m is 2048 bits
m is NOT prime
e is 17 bits
e is prime
n is 2048 bits
n is NOT prime
n' is 134176848 bits
resolving n' took 1159 seconds
Module VERIFIED
```