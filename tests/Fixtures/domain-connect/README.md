# Domain Connect test fixtures

- `cbox.dk.engage-sending.json`: the template the tests apply.
- `test-private.pem` / `test-public.pem`: an RSA 2048 keypair generated for
  these tests only. It signs nothing real and must never be published in DNS
  or used outside the test suite.
- `test-ec-public.pem`: a throwaway P-256 public key, used to check that
  only RSA keys are published (`openssl ecparam -name prime256v1 -genkey -noout | openssl ec -pubout`).
- `test-rsa-pkcs1-public.pem`: the test RSA public key in PKCS#1 form
  (`openssl rsa -in test-private.pem -RSAPublicKey_out`).
- `test-rsa-1024.pem`: a throwaway 1024-bit RSA private key (`openssl genrsa 1024`),
  used only to check that the signer refuses keys under 2048 bits.
- `server.php`: the `php -S` router for the `StreamTransport` loopback test
  (`/ok`, `/redirect`, `/big`, `/slow`, anything else 404).
- `reference-signature.txt`: the RS256 signature (RSA PKCS#1 v1.5 over
  SHA-256, standard base64) of the spec's example query, produced with the
  `openssl` CLI, independent of the library's signer:

```bash
openssl genrsa -out test-private.pem 2048
openssl rsa -in test-private.pem -pubout -out test-public.pem
printf '%s' 'a=1&b=2&ip=10.10.10.10&domain=example.net' \
  | openssl dgst -sha256 -sign test-private.pem | base64 | tr -d '\n' > reference-signature.txt
```

This is the same construction the reference Python `domainconnect` library
uses (`PKCS1_v1_5` + `SHA256` + `b64encode`).
