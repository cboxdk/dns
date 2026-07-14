---
title: Requirements
weight: 3
description: The PHP version and extensions this package requires, taken directly from composer.json.
---

# Requirements

These are the constraints the Composer resolver actually enforces, plus the
extensions the DNSSEC module needs at runtime. Nothing here is invented.

## Enforced by Composer

From `composer.json`:

| Requirement | Constraint | Why |
| --- | --- | --- |
| PHP | `^8.4` | Language baseline (developed and CI-tested on 8.4 and 8.5). |
| `ext-sockets` | `*` | The raw UDP/TCP transport of `SocketResolver`. |

There are **no** runtime package dependencies — this is a zero-dependency library.

## Needed by the DNSSEC module

The DNSSEC validator verifies signatures with two extensions. They are **not** hard
Composer constraints, because the resolver, domain verification, propagation, and
the non-DNSSEC diagnostics all work without them — only DNSSEC validation calls into
them:

| Extension | Used for |
| --- | --- |
| `ext-openssl` | RSA and ECDSA (P-256 / P-384) signature verification. |
| `ext-sodium` | Ed25519 signature verification. |

Both are part of a standard PHP distribution. If you validate DNSSEC on a build
that lacks them, verification of the affected algorithm family cannot succeed.

## Optional: internationalized names

| Extension | Used for |
| --- | --- |
| `ext-intl` | Punycode (IDN → A-label) conversion of non-ASCII domain names. |

Purely ASCII names need nothing extra. `ext-intl` is required only when you look up
a Unicode name (e.g. `blåbærgrød.dk`); without it, a non-ASCII name is refused
rather than silently queried as the wrong name. It is listed under Composer
`suggest`, not `require`.

## Development

Dev-only tooling (from `require-dev`), not needed to consume the package:

| Tool | Constraint |
| --- | --- |
| `laravel/pint` | `^1.18` |
| `pestphp/pest` | `^3.5 \|\| ^4.0` |
| `phpstan/phpstan` | `^2.0` |

## Framework

None. This library is framework-agnostic — it does not depend on Laravel or any
other framework, and it is namespaced `Cbox\Dns\`.
