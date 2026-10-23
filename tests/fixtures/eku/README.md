# Issuer ExtendedKeyUsage fixtures (#155)

Generated with OpenSSL 3.6.5 (EC P-256) for the issuer-EKU chaining tests.
Private keys are intentionally not committed; the recipe below regenerates the
family if the validity window ever matters.

Chain shape:

```text
root.crt -> inter_*.crt -> leaf_*.crt
```

`root.crt` is the loose PEM trust anchor (CA:TRUE, keyCertSign+cRLSign, no
EKU). Every other certificate is a base64 DER section in
`../fixtures.txtar`:

- `eku_inter_email_der` — CA with EKU=emailProtection only.
- `eku_leaf_server_der` — serverAuth leaf, SAN `victim.test`, issued by the
  emailProtection CA.
- `eku_inter_any_der` — CA with EKU=anyExtendedKeyUsage.
- `eku_leaf_any_der` — serverAuth leaf, SAN `victim.test`, issued by the
  anyEKU CA.
- `eku_inter_serverauth_der` — CA with EKU=serverAuth only.
- `eku_leaf_client_der` — clientAuth leaf (CN `client.test`), issued by the
  serverAuth-only CA.
- `eku_inter_plain_der` / `eku_leaf_plain_der` — no-EKU CA and its serverAuth
  `victim.test` leaf (permissive control).
- `eku_leaf_client_plain_der` — clientAuth leaf under the no-EKU CA
  (client-chain control).
- `root_email_only.crt` — a second anchor carrying EKU=emailProtection only,
  with `eku_anchor_email_inter_der` (no-EKU CA) and
  `eku_anchor_email_leaf_der` (serverAuth `victim.test` leaf) chaining to it.
  OpenSSL 3.6.5 rejects this chain for sslserver with error 26 at the
  anchor's own depth; tls matches by running the anchor through the same
  issuer-EKU check.

OpenSSL 3.6.5 ground truth (`openssl verify -CAfile root.crt -untrusted
<inter> <leaf>`):

| chain | `-purpose sslserver` | `-purpose sslclient` | no purpose |
| --- | --- | --- | --- |
| email inter + server leaf | error 26 at depth 1 | — | OK |
| anyEKU inter + server leaf | error 26 at depth 1 | — | OK |
| plain inter + server leaf | OK | — | OK |
| serverAuth inter + client leaf | — | error 26 at depth 1 | OK |

tls deliberately diverges from OpenSSL on the anyEKU row: Go crypto/x509 and
webpki treat id-kp-anyExtendedKeyUsage (2.5.29.37.0) as satisfying any role,
and tls follows them; OpenSSL's `xku_reject` has no anyEKU escape.

Anchor behavior: OpenSSL applies the purpose check to the trust anchor as
well — a root carrying EKU=emailProtection only anchors nothing for
sslserver (error 26 at the anchor's depth). tls matches: the anchor goes
through the same `verifyIssuerUsage` EKU check.

Regeneration recipe (OpenSSL 3.6.5):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout root.key -out root.crt -days 3650 -nodes -subj "/CN=eku-root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
# per intermediate: openssl req -newkey ec ... ; openssl x509 -req -CA root.crt
#   with basicConstraints=critical,CA:TRUE, keyUsage=critical,keyCertSign,cRLSign
#   and the extendedKeyUsage line from the table above
# per leaf: openssl x509 -req -CA <inter>.crt with CA:FALSE, digitalSignature,
#   the leaf EKU, and subjectAltName=DNS:victim.test for server leaves
openssl x509 -in <cert>.crt -outform der   # base64 into fixtures.txtar
```
