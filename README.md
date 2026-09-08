pkcs11Test: A PKCS#11 Test Suite
================================
[![CI](https://github.com/qpernil/pkcs11test/actions/workflows/ci.yml/badge.svg)](https://github.com/qpernil/pkcs11test/actions/workflows/ci.yml)

**Warning: Do not run this test suite against a PKCS#11 token that contains real data; some of the tests may erase or
  permanently lock the token.**

This repository holds a test suite for, and is therefore derived from, the
[RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)](http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptographic-token-interface-standard.htm).

The test suite uses the PKCS #11 2.2 API with selected later-version contracts, and covers:

- library management (`init.cc`)
- slot and token management (`slot.cc`)
- session management (`session.cc`, `login.cc`)
- object management (`object.cc`)
- key management (`key.cc`)
- symmetric encryption and decryption (`cipher.cc`)
- asymmetric encryption and decryption (`cipher.cc`)
- signing and verification (`sign.cc`, `hmac.cc`)
- message digesting (`digest.cc`)
- dual-function mechanisms (`dual.cc`)


To build the test program on Linux or macOS, run `make`. Google Test 1.10.0 is vendored.  To run the tests against
common Linux PKCS#11 implementations:

 - Run `make test_opencryptoki` to test against an
   [OpenCryptoKi](http://sourceforge.net/projects/opencryptoki/) [installation](https://packages.debian.org/wheezy/admin/opencryptoki).

This fork combines [Google's upstream](https://github.com/google/pkcs11test)
with [YubicoLabs' test extensions](https://github.com/YubicoLabs/pkcs11test) and
the fixture corrections described below. Both histories are preserved.

This is NOT an official Google product.

Additional make options:
 - `PKCS11_LONG_SIZE=32` - set `CK_LONG`/`CK_ULONG` size to `int32_t`/`uint32_t`. Normally set to `long int`, which is machine/compiler dependent.
 - `STRICT_P11=1` - use packed PKCS #11 structures; select this only when it matches the module ABI.

Example:
```
make PKCS11_LONG_SIZE=32 STRICT_P11=1
```

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
 - `-w name`: Restrict general wrapping tests to a named profile from the fixture catalog (for example `AES-KWP` or `3DES-ECB`); the default `auto` runs all compatible profiles. An unsupported selection reports SKIPPED.
 - `-S index`: Select a token-present slot by zero-based index.
 - `-U pwd`, `-O pwd`: Supply expected reset user and SO PINs for fixtures that need them.
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
attribute-policy tests use AES-128 or generic secrets. Algorithm-specific cipher
cases retain their algorithms and report SKIPPED when unavailable. Named
cipher-vector cases import keys and require only the advertised encryption
operation, independently of key-generation support. IV checks
report SKIPPED for ECB, where no IV is used. RSA fixtures use
1024- or 2048-bit keys; a token's key-size and security policies can further
restrict which fixtures it supports.

The general `WrapUnwrap`, `WrapInvalid`, `UnwrapInvalid`, and `TookanAttackA1`
cases run every compatible profile from a standard symmetric-wrapping catalog:
AES-KW/KW-PAD/KWP and AES, 3DES, or DES in ECB, CBC, or CBC-PAD mode. Selection
requires advertised key generation and the operations used by that case, plus
a compatible AES key size. Unpadded AES fixtures use block-aligned payloads;
fixed-size DES/3DES do not use the mechanism's min/max key-size fields. New or
vendor-specific wrapping schemes need an explicit fixture definition.

The round-trip test requires wrap and unwrap; it additionally compares direct
decryption when advertised. The security test requires wrap and decrypt and
first proves that the same wrapping key can export an extractable control key.
The RSA Tookan A2 case also wraps and decrypts a control key before checking
protected-key rejection; unsupported execution of an advertised operation fails.
Each selected profile is named in output and failure traces. No compatible
profile produces a named SKIPPED result. Once a profile qualifies, generation
or operation errors remain failures, including `CKR_FUNCTION_NOT_SUPPORTED`.
The catalog is chosen from standard contracts, independently of the module
under test; no token manufacturer or implementation name is special-cased.

Run the seven selector/discovery regressions without a PKCS #11 module using
`make check`. They cover absent capabilities, required flags, multiple eligible
profiles, key-size intersections, IV initialization, and discovery errors.

The shared key helpers create session objects by default. Secret keys default
to public, non-sensitive, and extractable so value comparison and wrapping
have explicit prerequisites; individual security tests override those policies.
Public session-object fixtures run without login in read-only sessions.
Private RSA fixtures authenticate when the token requires login; only
explicit token-object creation requires a read/write session. Dedicated
authentication and read/write object tests remain separate.
Explicit token-object attributes are preserved. Attribute storage
remains alive through generation, and object-search capacities count handles,
not bytes.

`PublicExponent4Bytes` supplies complete boolean attributes and tests the
unsigned big-endian value `00 01 00 01`. RSA encryption checks ciphertext length
against the actual modulus size. HMAC generation supplies `CKA_VALUE_LEN`. Generic generation requests
`CKK_GENERIC_SECRET`; separate typed-generation cases use the corresponding
standard SHA key-generation mechanisms and verify the resulting key type.
Secret-key import checks use a complete AES key, not an empty value. HMAC
vectors include the original long-key cases and preserve their published key
bytes. Named generic-secret and typed-key cases cover empty messages and
keys on both sides of the 64- and 128-byte block boundaries. Unsupported
short-key policies produce an explicit skip for the specific case.

Token initialization verifies the PIN supplied to `C_InitPIN`. The wrong-SO-PIN
fixture preserves the supplied PIN's length and initial character family to
avoid conflating authentication with PIN format validation. Retry-warning flags
are optional; incorrect-PIN rejection and recovery with the correct PIN remain
required. RNG-seeding tests keep initialization and invalid-session checks
independent of token RNG flags; a genuine unsupported function stub is an
explicit skip. The bad-argument case permits the independently applicable
seeding-capability error.

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
