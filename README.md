pkcs11Test: A PKCS#11 Test Suite
================================
[![Travis](https://img.shields.io/travis/Yubico/pkcs11test.svg)](https://travis-ci.org/Yubico/pkcs11test)

**Warning: Do not run this test suite against a PKCS#11 token that contains real data; some of the tests may erase or
  permanently lock the token.**

This repository holds a test suite for, and is therefore derived from, the
[RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)](http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptographic-token-interface-standard.htm).

To build the test program on Linux, just run `make`.  To run the tests against
common Linux PKCS#11 implementations:

 - Run `make test_chaps` to test against a
   [Chaps](https://github.com/google/chaps-linux) installation.
 - Run `make test_opencryptoki` to test against an
   [OpenCryptoKi](http://sourceforge.net/projects/opencryptoki/) [installation](https://packages.debian.org/wheezy/admin/opencryptoki).

This is NOT an official Google product.


Test Options
------------

The test program requires the following command-line parameters to be set:

 - `-m libname`: Provide the name of the PKCS#11 library to test.
 - `-l libpath`: Provide the path holding the PKCS#11 library.

There are also several optional command-line parameters:

 - `-s slotid`: Provide the slot ID that will be used for the tests
 - `-v`: Generate verbose output.
 - `-u pwd`: Provide the user PIN/password.
 - `-o pwd`: Provide the security officer PIN/password.
 - `-I`: Perform token initialization tests. **This will wipe the contents of the PKCS#11 token**

The test program uses [Google Test](https://code.google.com/p/googletest/), and
the
[Google Test command line options](https://code.google.com/p/googletest/wiki/V1_6_AdvancedGuide#Running_Test_Programs:_Advanced_Options)
are also available.  In particular, `--gtest_filter=<filter>` can be used to run a subset of the tests.

Fixture contracts
-----------------

Fixtures use standard PKCS #11 behavior, explicit key policies, and advertised
capabilities. Missing mechanisms or required operation flags produce a named
skip; other discovery errors remain failures. General object, digest-key, and
attribute-policy tests use AES-128 or generic secrets. DES-specific cipher and
wrap tests retain DES and skip when it is unavailable. RSA fixtures use
1024- or 2048-bit keys; a token's key-size and security policies can further
restrict which fixtures it supports.

The shared key helpers create session objects by default. Secret keys default
to public, non-sensitive, and extractable so value comparison and wrapping
have explicit prerequisites; individual security tests override those policies.
Private RSA keys are private objects and their fixtures authenticate before
creation. Explicit token-object attributes are preserved. Attribute storage
remains alive through generation, and object-search capacities count handles,
not bytes.

`PublicExponent4Bytes` supplies complete boolean attributes and tests the
unsigned big-endian value `00 01 00 01`. RSA encryption checks ciphertext length
against the actual modulus size. HMAC generation supplies `CKA_VALUE_LEN`.
Secret-key import checks use a complete AES key, not an empty value.

Token initialization verifies the PIN supplied to `C_InitPIN`. The wrong-SO-PIN
fixture preserves the supplied PIN's length and initial character family to
avoid conflating authentication with PIN format validation. Retry-warning flags
are optional; incorrect-PIN rejection and recovery with the correct PIN remain
required.

Size-query tests check that input is not consumed: encryption can continue with
Update/Final and recover the original plaintext, and digest Final returns the
empty-message digest. PKCS #11 3.x NULL-mechanism tests cancel active encryption
and decryption; version 2.x retains the invalid-argument checks. A reported
cancellation failure is an explicit unsupported subcase. Mechanism enumeration
checks defined flag bits for the advertised interface version rather than using
this fork's incomplete mechanism tables as an exhaustive capability registry.

The Tookan-derived policy tests require sensitive or non-extractable keys to
hide their plaintext values. Wrap-rejection tests explicitly make the victim
non-extractable: sensitivity alone does not prohibit wrapping. Attempts to
relax either policy must fail and leave the attributes unchanged.

These contracts follow the [PKCS #11 2.40 base specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html),
the [3.1 specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html),
and the [generic-secret generation definition](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.pdf).
A successful run establishes only the executed cases on the selected token;
unsupported cases are not conformance successes.
