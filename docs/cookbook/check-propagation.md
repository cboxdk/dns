---
title: Check propagation
weight: 53
description: Compare the authoritative answer against public resolvers to tell "still rolling out" apart from "misconfigured".
---

# Check propagation

## The quick check

```php
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Propagation\PropagationStatus;

$dns = new Dns;

$report = $dns->checkPropagation('www.example.com', RecordType::A, 'example.com');

match ($report->status) {
    PropagationStatus::Propagated   => 'Everyone agrees — the change is live.',
    PropagationStatus::Pending      => 'Correct at the source; some resolvers are still stale.',
    PropagationStatus::Misconfigured => 'The authoritative answer itself is missing.',
};
```

## Show what's lagging

```php
$report->authoritativeValues;   // the source-of-truth set

foreach ($report->stale() as $result) {
    printf("%s still serves %s\n", $result->nameserver, implode(', ', $result->values));
}
```

`stale()` returns the `ResolverResult`s that don't yet agree with the authoritative
set; each carries the `nameserver`, its returned `values`, the `agrees` flag, and an
optional provider `label`.

## Poll the full named registry

`checkPropagation()` polls a lean six-IP panel. For a labelled check across the full
15-provider registry, build the checker directly:

```php
use Cbox\Dns\Propagation\PropagationChecker;

$report = (new PropagationChecker($dns->resolver(), $dns->authoritative()))
    ->checkAcrossProviders('www.example.com', RecordType::A, 'example.com');

foreach ($report->results as $result) {
    printf("%s (%s): %s\n", $result->label, $result->nameserver, $result->agrees ? 'ok' : 'stale');
}
```

## Read this honestly

This is a **cache-diversity** signal across independent recursive operators, not
global geographic propagation — every provider is anycast, so you sample operators,
not locations. The reliable signal is the authoritative-vs-recursive diff. See
[Propagation](../core-concepts/propagation.md) and the
[provider registry](../diagnostics/propagation-providers.md).
