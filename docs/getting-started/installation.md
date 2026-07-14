---
title: Installation
weight: 11
description: Install cboxdk/dns with Composer, confirm the required extensions, and make a first call.
---

# Installation

```bash
composer require cboxdk/dns
```

## Extensions

- **`ext-sockets`** is required and enforced by Composer — it is the transport for
  the raw resolver.
- **`ext-openssl`** and **`ext-sodium`** are needed only for [DNSSEC](../dnssec/_index.md)
  signature verification. Both ship with a stock PHP build. Confirm them with:

```bash
php -m | grep -E 'sockets|openssl|sodium'
```

See [Requirements](../requirements.md) for the full matrix.

## First call

```php
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;

$dns = new Dns;

$response = $dns->lookup('example.com', RecordType::A);

var_dump($response->values());
```

`new Dns` with no arguments uses `SocketResolver`, which queries `1.1.1.1` by
default over UDP (retrying over TCP if the answer is truncated). To point it
elsewhere, construct the resolver yourself and inject it:

```php
use Cbox\Dns\Resolvers\SocketResolver;

$dns = new Dns(new SocketResolver(defaultNameserver: '8.8.8.8', timeout: 2.0));
```

Or resolve over DNS-over-HTTPS instead — see [Resolvers](../core-concepts/resolvers.md).

## Next

- [Testing](testing.md) — drive everything offline.
- [Quickstart](../quickstart.md) — every capability in one read.
