<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;

/**
 * Wires a {@see DiagnosticContext} around a {@see FakeResolver} so a single check
 * can be driven entirely offline, and exposes small helpers to assert on findings.
 */
final class DiagnosticFixture
{
    public static function context(FakeResolver $fake, string $domain = 'example.com', ?DnssecValidator $dnssec = null): DiagnosticContext
    {
        $authoritative = new AuthoritativeResolver($fake);

        return new DiagnosticContext(
            $domain,
            $fake,
            $authoritative,
            $dnssec ?? new DnssecValidator($fake),
            new PropagationChecker($fake, $authoritative),
        );
    }

    /**
     * Run a check against a fake-backed context and return its findings.
     *
     * @return list<Finding>
     */
    public static function run(Check $check, FakeResolver $fake, string $domain = 'example.com'): array
    {
        return $check->run(self::context($fake, $domain));
    }

    /**
     * The `check` identifiers of a set of findings, in order.
     *
     * @param  list<Finding>  $findings
     * @return list<string>
     */
    public static function checks(array $findings): array
    {
        return array_map(static fn (Finding $f): string => $f->check, $findings);
    }

    /**
     * The findings whose `check` identifier matches.
     *
     * @param  list<Finding>  $findings
     * @return list<Finding>
     */
    public static function withCheck(array $findings, string $check): array
    {
        return array_values(array_filter($findings, static fn (Finding $f): bool => $f->check === $check));
    }
}
