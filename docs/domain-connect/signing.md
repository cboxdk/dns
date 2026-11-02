---
title: Signing
weight: 47
description: The RS256 signature on the apply URL, the sig and key parameters, the _dcpubkeyv1 TXT record that publishes the public key, and key rotation.
---

# Signing

A DNS provider applies a template only to the domain and variables the service
provider asked for. To prove the apply URL came from you and was not edited on the
way, the synchronous flow signs it: you sign the query string with a private key,
and the DNS provider verifies it with the public key you publish in DNS.

## What is signed

`SyncUrlBuilder` (behind `DomainConnect::applyUrl()`) builds the query string from
the `ApplyRequest`, in this order:

| Parameter | When |
| --- | --- |
| `domain` | Always: the zone apex. |
| `host` | Only when the zone is not the apex. |
| `redirect_uri` | When the request has one. |
| `state` | When the request has one. |
| each template variable | In the order the template first uses them. |
| `groupId` | When groups were requested, comma-joined. |

The pairs are encoded with `http_build_query(..., PHP_QUERY_RFC3986)`, and the
signature is computed over **exactly those encoded bytes**. Then two parameters are
appended, unsigned:

```
https://connect.provider.example/v2/domainTemplates/providers/example.com/services/mail/apply
  ?domain=acme.com&state=...&token=abc123
  &sig=<base64 signature, URL-encoded>
  &key=_dcpubkeyv1
```

- `sig` is the RS256 signature (RSA PKCS#1 v1.5 over SHA-256), standard base64,
  then URL-encoded.
- `key` is the host label of your public key. The DNS provider looks the key up at
  `<key>.<syncPubKeyDomain>`, where `syncPubKeyDomain` comes from your template.

Before signing, the request is checked against the template, so a bad request never
becomes a URL (`InvalidApplyRequest`): every variable the template uses must have a
value, no unknown variables or groups may be passed, and a template variable may not
be named like one of the flow's own parameters (`domain`, `host`, `redirect_uri`,
`state`, `groupId`, `sig`, `key`, compared case-insensitively). A provider without
`urlSyncUX`, or a template with `syncBlock: true`, throws `SyncFlowUnavailable`.

The library does not check that `redirectUri` is on the template's
`syncRedirectDomain`; the DNS provider does.

## The signer

`Contracts\Signer` has one method, `sign(string $query): string`, returning standard
base64. The shipped implementation is `Signers\OpenSslRs256Signer`:

```php
use Cbox\Dns\DomainConnect\Signers\OpenSslRs256Signer;

$signer = new OpenSslRs256Signer($privateKeyPem);   // PEM, RSA only
```

It requires `ext-openssl`, accepts only an RSA private key, and calls `openssl_sign()`
with `OPENSSL_ALGO_SHA256`. The algorithm is fixed; no cryptography is implemented
here. The signature format is checked in the test suite against a reference
signature produced independently with the `openssl` CLI.

## Publishing the public key

`PublicKeyRecords::for(string $publicKeyPem, int $chunk = 200): list<string>` turns
your public key into the TXT strings to publish:

```php
use Cbox\Dns\DomainConnect\PublicKeyRecords;

PublicKeyRecords::for(file_get_contents('domain-connect-public.pem'));
// [
//     'p=1,a=RS256,d=MIIBIjANBgkqhkiG9w0BAQEFAA...',
//     'p=2,a=RS256,d=Zv0/GpqoSl/OnDAXn/ePg6LnnC...IDAQAB',
// ]
```

Each string is `p=<part>,a=RS256,d=<chunk>`: the base64 body of the key in SPKI form
(`BEGIN PUBLIC KEY`), split into numbered chunks so each TXT string stays under the
255-byte limit (`$chunk` may be 1 to 235). Publish every string as a separate TXT
record at `_dcpubkeyv1.<syncPubKeyDomain>`. A 2048-bit key gives two records.

It accepts an RSA public key in SPKI or PKCS#1 PEM and always publishes SPKI. Any
other input — an EC key, garbage, or a **private key** — throws `InvalidPayload`,
so a private key cannot end up in DNS by mistake. `PublicKeyRecords::toPem()` does
the reverse: it rebuilds the PEM from the published strings, in any order, which is
useful to confirm that what is in DNS matches the key you sign with.

## Rotating the key

The DNS provider reads the key from the host named in `key`, so a rotation never
needs a moment where signatures and DNS disagree:

1. Generate a new keypair and publish its records at `_dcpubkeyv2.<syncPubKeyDomain>`,
   next to the existing `_dcpubkeyv1`.
2. Switch to the new private key and pass `keyHost: '_dcpubkeyv2'` to
   `Dns::domainConnect()` (or to `SyncUrlBuilder`). New URLs now say `key=_dcpubkeyv2`.
3. Once apply URLs signed with the old key are no longer in use, remove the
   `_dcpubkeyv1` records.

## Test keypair

`tests/Fixtures/domain-connect/` holds an RSA 2048 keypair (`test-private.pem`,
`test-public.pem`) generated for the test suite only, plus the reference signature.
It signs nothing real. Never publish it in DNS or use it outside the tests.
