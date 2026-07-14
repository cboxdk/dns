---
title: Checks catalog
weight: 41
description: Every diagnostic check in the default catalog, the DKIM opt-in check, the findings model, and how to add your own.
---

# Checks catalog

## The findings model

Each check returns zero or more `Finding`s. A `Finding` carries:

| Field | Meaning |
| --- | --- |
| `severity` | `Severity::Error` \| `Warning` \| `Info` |
| `category` | e.g. `Delegation`, `Nameservers`, `Email`, `DNSSEC` |
| `check` | a stable machine id, e.g. `delegation.match` |
| `message` | human-readable text |
| `context` | machine-readable bag of the raw values behind the message |

Severity means:

- **Error** — a misconfiguration that breaks resolution, mail, or trust.
- **Warning** — works today, but fragile, non-redundant, or below best practice.
- **Info** — an observation or a healthy result worth surfacing.

`Report::passed()` is a clean bill of health: no errors *and* no warnings.

## The default catalog

`Diagnostics::run()` executes these checks, in report order. Every check turns a
DNS-level failure into a `Finding` rather than throwing.

| Category | Check ids | What it verifies |
| --- | --- | --- |
| **Delegation** | `delegation.ns`, `delegation.match`, `delegation.glue` | The zone has NS records; the parent's NS set matches the zone's own; in-zone nameservers have glue at the parent. |
| **Nameservers** | `ns.count`, `ns.cname`, `ns.resolve`, `ns.respond`, `ns.authoritative`, `ns.lame`, `ns.recursion` | At least two NS (RFC 1034); none a CNAME (RFC 2181); each resolves to a public IP; each responds and answers authoritatively (not "lame"); none offers open recursion for a foreign name. |
| **SOA** | `soa.presence`, `soa.parse`, `soa.serial`, `soa.mname`, `soa.timers` | SOA read from each authoritative NS; every server serves the same serial; MNAME is a listed nameserver; refresh/retry/expire/minimum timers are internally sane. |
| **Email** (MX) | `mx.presence`, `mx.target`, `mx.redundancy`, `mx.ptr`, `mx.fcrdns` | MX exists; each exchange is a resolvable public hostname (never an IP literal or CNAME, RFC 2181 §10.3); more than one for redundancy; each mail IP has a PTR that forward-confirms (FCrDNS). |
| **Email** (SPF) | `spf.presence`, `spf.lookups`, `spf.all` | Exactly one `v=spf1` record (RFC 7208); the static DNS-lookup budget is not exceeded; it does not end in a permissive `+all`. |
| **Email** (DMARC) | `dmarc.presence`, `dmarc.policy` | A DMARC record at `_dmarc.<domain>`; a valid, enforcing `p=` policy (absent, malformed, or `p=none` is a Warning). |
| **CAA** | `caa.presence` | Whether the apex publishes a CAA record. Both outcomes are Info — absence is not a fault. |
| **DNSSEC** | `dnssec.chain` | Wraps the [DNSSEC validator](../dnssec/validation.md): `secure`/`insecure` is Info; `bogus` is an Error. |
| **Propagation** | (via `PropagationCheck`) | The apex A record's authoritative-vs-recursive [propagation](../core-concepts/propagation.md): `Propagated` is Info; `Pending`/`Misconfigured` is a Warning. |

## The DKIM check (opt-in)

DKIM cannot be probed without knowing the selector — there is no way to enumerate
selectors over DNS — so `DkimCheck` is **not** in the default set. Run it explicitly
with a selector via `runWith()`:

```php
use Cbox\Dns\Diagnostics\Diagnostics;
use Cbox\Dns\Diagnostics\Checks\DkimCheck;

$diagnostics = new Diagnostics($dns->resolver());

$report = $diagnostics->runWith('example.com', [new DkimCheck('selector1')]);
// checks selector1._domainkey.example.com -> dkim.presence / dkim.revoked
```

## Adding your own checks

A check implements `Cbox\Dns\Diagnostics\Contracts\Check`:

```php
use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;

final class MyCheck implements Check
{
    /** @return list<Finding> */
    public function run(DiagnosticContext $ctx): array
    {
        $addresses = $ctx->addresses($ctx->domain);   // resolved via the injected resolver

        return $addresses === []
            ? [Finding::warning('Custom', 'my.check', 'Apex has no A/AAAA.')]
            : [Finding::info('Custom', 'my.check', count($addresses).' apex addresses.')];
    }
}
```

`DiagnosticContext` exposes the target `domain` plus the injected collaborators —
`resolver`, `authoritative`, `dnssec`, `propagation` — and helpers `nameservers()`
and `addresses($host)`. Run a custom list, optionally alongside the defaults:

```php
$diagnostics->runWith('example.com', [
    ...Diagnostics::defaultChecks(),
    new MyCheck,
]);
```
