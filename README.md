# PQ-SIGNTOOL - Poor man's post quantum file signing

This is a simple command line utility to batch sign files with (conjenctured)
quantum secure signature algorithm.

First, you generate key:

```
pqs.exe -phrase -key mykey
```

It will ask for passphrase which will be used as a seed for a key. Only use
this if your phrase is good (it will be hardened with Argon2 for a bit; too).

Otherwies just hit enter, and it will generate random key. You'll have save both
key files.

Next, we can sign some files:

```
pqs.exe -key mykey somefile1 somefile2...
```

And to verify:

```
pqs.exe -key mykey.pub somefile1 somefile2...
```

You can verify the source code with my key:

``
pqs.exe -key dis.pub pqs.go`
``

You have to distribute only the .pub file once, and then whoever has it can
verify that a file is yours if it is accompanied with .pqsig.

While the output is somewhat verbose, it comes all to stderr. stdout prints
only the files which are being signed, or which are *succesfuly* verified.
Should any signing or checking fail, it returns 1 exit code.

## Dual mode signatures

Dilithium is the latest iteration of lattice signatures, and it's quite
possible the algorithm will be broken (it happened in the past). pqs implements
dual signing for this reason - public key and signature both include ordinary
ed25519 too (and the secret key seed is shared between the two algorithms).

So if one algorithm is broken, the other can save the day - meaning it can't
get worse than conventional crypto, only better.


