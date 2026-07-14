#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * License gate. Fails (exit 1) if any installed dependency is not offered under
 * at least one allowed license. Dual-licensed packages (SPDX "OR", e.g. nette's
 * "BSD-3-Clause OR GPL-3.0-only") pass as long as ONE choice is allowed — which
 * is exactly the choice we exercise. Run: `composer license-check`.
 */
const ALLOWED = [
    'MIT', 'MIT-0', 'ISC', '0BSD', 'Unlicense', 'WTFPL', 'CC0-1.0',
    'BSD-2-Clause', 'BSD-3-Clause', 'BSD-3-Clause-Clear', 'BSD-4-Clause',
    'Apache-2.0', 'Apache2', 'BSL-1.0', 'Zlib', 'PHP-3.01',
];

/** Packages permitted despite a missing/odd license field, with justification. */
const EXCEPTIONS = [
    // e.g. 'vendor/pkg' => 'public domain, confirmed upstream',
];

$lockPath = dirname(__DIR__).'/composer.lock';

if (! is_file($lockPath)) {
    fwrite(STDERR, "composer.lock not found; run `composer install` first.\n");
    exit(2);
}

$lock = json_decode((string) file_get_contents($lockPath), true, 512, JSON_THROW_ON_ERROR);

$includeDev = in_array('--dev', $argv, true);
$packages = $lock['packages'] ?? [];

if ($includeDev) {
    $packages = array_merge($packages, $lock['packages-dev'] ?? []);
}

$violations = [];
$checked = 0;

foreach ($packages as $package) {
    $name = (string) ($package['name'] ?? '?');
    $checked++;

    if (isset(EXCEPTIONS[$name])) {
        continue;
    }

    $license = $package['license'] ?? [];
    $rendered = renderLicense($license);

    if ($rendered === '') {
        $violations[$name] = '(no license declared)';

        continue;
    }

    if (! isPermissive($license)) {
        $violations[$name] = $rendered;
    }
}

/**
 * Whether a composer license field is satisfiable under a permissive license.
 * SPDX semantics are honoured: an array (composer's disjunctive form) or an `OR`
 * expression passes if ANY choice is permissive; an `AND` expression requires
 * EVERY conjunct to be permissive (you must comply with all of them).
 *
 * @param  list<string>|string  $license
 */
function isPermissive(array|string $license): bool
{
    if (is_array($license)) {
        // Composer treats an array of licenses as a choice (disjunctive).
        foreach ($license as $item) {
            if (is_string($item) && isPermissiveExpression($item)) {
                return true;
            }
        }

        return false;
    }

    return isPermissiveExpression($license);
}

/**
 * Evaluate a single SPDX license expression, honouring parentheses and the SPDX
 * precedence where AND binds tighter than OR. OR is satisfied if either side is
 * permissive; AND requires both sides. Returns whether the expression is
 * satisfiable under the permissive allow-list.
 */
function isPermissiveExpression(string $expression): bool
{
    $tokens = spdxTokens($expression);
    $pos = 0;
    $result = spdxOr($tokens, $pos);

    // A trailing unparsed token means we could not understand the expression;
    // fail closed rather than pass an expression we did not fully evaluate.
    return $pos === count($tokens) && $result;
}

/**
 * @return list<string>
 */
function spdxTokens(string $expression): array
{
    preg_match_all('/\(|\)|[^\s()]+/', $expression, $m);

    return $m[0];
}

/**
 * expr := term (OR term)*
 *
 * @param  list<string>  $tokens
 */
function spdxOr(array $tokens, int &$pos): bool
{
    $value = spdxAnd($tokens, $pos);

    while (($tokens[$pos] ?? null) !== null && strcasecmp($tokens[$pos], 'OR') === 0) {
        $pos++;
        $value = spdxAnd($tokens, $pos) || $value;
    }

    return $value;
}

/**
 * term := factor (AND factor)*
 *
 * @param  list<string>  $tokens
 */
function spdxAnd(array $tokens, int &$pos): bool
{
    $value = spdxFactor($tokens, $pos);

    while (($tokens[$pos] ?? null) !== null && strcasecmp($tokens[$pos], 'AND') === 0) {
        $pos++;
        $value = spdxFactor($tokens, $pos) && $value;
    }

    return $value;
}

/**
 * factor := '(' expr ')' | identifier ['WITH' exception]
 *
 * @param  list<string>  $tokens
 */
function spdxFactor(array $tokens, int &$pos): bool
{
    $token = $tokens[$pos] ?? null;

    if ($token === '(') {
        $pos++;
        $value = spdxOr($tokens, $pos);

        if (($tokens[$pos] ?? null) === ')') {
            $pos++;
        }

        return $value;
    }

    if ($token === null || $token === ')') {
        return false;
    }

    $pos++;
    $identifier = $token;

    // An SPDX "WITH <exception>" narrows a permissive base license; judge on the
    // base identifier (e.g. "Apache-2.0 WITH LLVM-exception" → Apache-2.0).
    if (($tokens[$pos] ?? null) !== null && strcasecmp($tokens[$pos], 'WITH') === 0) {
        $pos += 2; // consume WITH and the exception id
    }

    return in_array($identifier, ALLOWED, true);
}

/**
 * A human-readable rendering of a composer license field for the failure report.
 *
 * @param  list<string>|string  $license
 */
function renderLicense(array|string $license): string
{
    if (is_array($license)) {
        return implode(' OR ', array_filter($license, 'is_string'));
    }

    return trim($license);
}

$scope = $includeDev ? 'production + dev' : 'production';

if ($violations !== []) {
    fwrite(STDERR, "License check FAILED ({$scope}): disallowed or missing licenses\n\n");
    foreach ($violations as $name => $license) {
        fwrite(STDERR, sprintf("  %-45s %s\n", $name, $license));
    }
    fwrite(STDERR, "\nAllowed: ".implode(', ', ALLOWED)."\n");
    fwrite(STDERR, "If a flagged package is genuinely fine, add it to EXCEPTIONS with a reason.\n");
    exit(1);
}

echo "License check passed: all {$checked} {$scope} dependencies are permissively licensed.\n";
exit(0);
