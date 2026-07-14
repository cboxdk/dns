---
title: Run a health check
weight: 52
description: Diagnose a domain, group the findings by severity or category, and gate on a clean bill of health.
---

# Run a health check

## Diagnose and act

```php
use Cbox\Dns\Dns;

$dns = new Dns;

$report = $dns->diagnose('example.com');

if ($report->passed()) {
    // No errors and no warnings.
}

if ($report->hasErrors()) {
    // At least one Error-severity finding — something is broken.
}
```

## Iterate the findings

```php
foreach ($report->findings as $finding) {
    printf(
        "[%s] %s / %s — %s\n",
        $finding->severity->value,   // "error" | "warning" | "info"
        $finding->category,          // "Delegation", "Email", "DNSSEC", ...
        $finding->check,             // "delegation.match", "mx.redundancy", ...
        $finding->message,
    );

    // $finding->context holds the raw values behind the message.
}
```

## Group for a report or dashboard

```php
$report->bySeverity();   // ['error' => Finding[], 'warning' => Finding[], 'info' => Finding[]]
$report->byCategory();   // ['Delegation' => Finding[], 'Nameservers' => Finding[], ...]
```

Only severities/categories that actually occurred appear as keys.

## Add a DKIM check

The DKIM check is opt-in because it needs a selector. Run it alongside the defaults:

```php
use Cbox\Dns\Diagnostics\Diagnostics;
use Cbox\Dns\Diagnostics\Checks\DkimCheck;

$report = (new Diagnostics($dns->resolver()))->runWith('example.com', [
    ...Diagnostics::defaultChecks(),
    new DkimCheck('selector1'),
]);
```

See the [checks catalog](../diagnostics/checks.md) for every check and how to write
your own.
