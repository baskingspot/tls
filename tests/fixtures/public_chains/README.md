# Public RSA chain fixtures (#215)

These certificates are public captures. They contain no private keys.

The presented chains came from `openssl s_client -showcerts` on 2026-11-22.
The hosts were `google.com`, `www.cloudflare.com`, and `example.com`.
Each chain includes the cross-signed root that the server presented.

The RSA issuer roots came from these public locations:

- GlobalSign R1: `https://secure.globalsign.com/cacert/root-r1.crt`
- AAA Certificate Services: `http://crt.sectigo.com/AAACertificateServices.crt`

The SHA-256 fingerprints are:

- GlobalSign R1: `EBD41040E4BB3EC742C9E381D31EF2A41A48B6685C96E7CEF3C1DF6CD4331C99`
- AAA Certificate Services: `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4`

The tests anchor each presented chain at its RSA issuer root.
This path verifies the RSA PKCS#1 v1.5 signature on the cross-signed root.
The fixed validation time is 2026-11-22 09:23:03 UTC.
The tests also check the leaf hostname.

The DER bytes live as base64 sections in `../fixtures.txtar`.
The test trust bundle is built directly from those sections at the fixed validation time.
OpenSSL 3.6.5 verified all three complete chains through these roots during capture.
