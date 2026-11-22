# Wycheproof RSA vectors (#215)

These files are unmodified Wycheproof v1 JSON vectors.
The source revision is `65ca494727a52944c204441c860b039e6786b99b`.
The files came from `C2SP/wycheproof/testvectors_v1`.

The PKCS#1 v1.5 files cover SHA-256, SHA-384, and SHA-512.
They contain 259 cases per hash.
The tests accept `valid` cases and reject `invalid` cases.
The implementation rejects the single `acceptable` case per file.
That case omits the NULL parameter from the DigestInfo AlgorithmIdentifier.
Strict DER comparison rejects it, which Wycheproof permits.

The PSS files cover SHA-256 with salt 32, SHA-384 with salt 48, and
SHA-512 with salt 64. They contain 108, 141, and 179 cases.
The tests accept `valid` cases and reject `invalid` cases.
Every PSS case has an explicit `valid` or `invalid` result.

The tests also truncate a valid signature and require rejection.
No test downloads vectors at run time.

SHA-256 checksums:

- `rsa_signature_2048_sha256_test.json`: `94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393`
- `rsa_signature_3072_sha384_test.json`: `73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae`
- `rsa_signature_4096_sha512_test.json`: `9d6e67b1eb0d7040db411835238efd20e9302399a258bdff82de3f38e0f2855a`
- `rsa_pss_2048_sha256_mgf1_32_test.json`: `7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c`
- `rsa_pss_2048_sha384_mgf1_48_test.json`: `66d464778b0b2f683a1d1a20e94f77e9472b8cc393b45f423fa08a48e677063c`
- `rsa_pss_4096_sha512_mgf1_64_test.json`: `c93ceaa56a190c9fd4707441c5c6a75839f108202d88aec891697f9623042547`
