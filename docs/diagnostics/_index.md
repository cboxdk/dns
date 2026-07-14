---
title: Diagnostics
weight: 40
description: The intoDNS/MxToolbox-style diagnostics engine — the check catalog, findings model, and propagation provider registry.
---

# Diagnostics

`Diagnostics` runs an intoDNS/MxToolbox-style catalog of checks against a domain and
aggregates every observation into a structured `Report`. All DNS reaches through the
composed resolvers, so a `FakeResolver` drives the whole engine offline, and a single
check throwing never aborts the run.

- **[Checks catalog](checks.md)** — every check the engine runs, what it flags, and
  how to add your own.
- **[Propagation providers](propagation-providers.md)** — the named public-resolver
  registry used by propagation checks.

## At a glance

```php
use Cbox\Dns\Dns;

$report = $dns->diagnose('example.com');

$report->passed();      // no errors AND no warnings
$report->hasErrors();
$report->bySeverity();  // grouped by "error" / "warning" / "info"
$report->byCategory();  // grouped by "Delegation" / "Email" / ...

foreach ($report->findings as $finding) {
    // $finding->severity (enum), ->category, ->check, ->message, ->context
}
```

## Scope

This is a **DNS-only** engine. Live SMTP diagnostics (banner / STARTTLS /
open-relay), RBL/blacklist lookups, and geo-distributed propagation vantage points
are deliberately **out of v1** — they need network egress or third-party
infrastructure that cannot be exercised offline — and are tracked as roadmap, not
stubbed.
