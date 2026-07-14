<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Diagnostics\Checks\CaaCheck;
use Cbox\Dns\Diagnostics\Checks\DelegationCheck;
use Cbox\Dns\Diagnostics\Checks\DkimCheck;
use Cbox\Dns\Diagnostics\Checks\DmarcCheck;
use Cbox\Dns\Diagnostics\Checks\DnssecCheck;
use Cbox\Dns\Diagnostics\Checks\MxCheck;
use Cbox\Dns\Diagnostics\Checks\NameserverCheck;
use Cbox\Dns\Diagnostics\Checks\PropagationCheck;
use Cbox\Dns\Diagnostics\Checks\SoaCheck;
use Cbox\Dns\Diagnostics\Checks\SpfCheck;
use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\Testing\FakeResolver;
use Throwable;

/**
 * The intoDNS/MxToolbox-style orchestrator. It builds a {@see DiagnosticContext}
 * from the injected resolvers, runs each {@see Check} against a domain, and
 * aggregates every {@see Finding} into a single {@see Report}.
 *
 * All DNS reaches through the composed collaborators, so a
 * {@see FakeResolver} drives the whole engine offline. A single
 * check throwing does not abort the run — its failure is caught and recorded so the
 * report stays complete.
 *
 * Scope: this is a DNS-only engine. Live SMTP diagnostics (banner/STARTTLS/open
 * relay), RBL/blacklist lookups, and geo-distributed propagation vantage points are
 * deliberately out of v1 — they need network egress or third-party infrastructure
 * that cannot be exercised offline — and are tracked as roadmap, not stubbed.
 */
class Diagnostics
{
    private readonly AuthoritativeResolver $authoritative;

    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
    ) {
        $this->authoritative = new AuthoritativeResolver($this->resolver);
    }

    /**
     * Run the default check set against `$domain`.
     */
    public function run(string $domain): Report
    {
        return $this->runWith($domain, self::defaultChecks());
    }

    /**
     * Run a specific list of checks against `$domain` — the seam for adding a
     * selector-scoped {@see DkimCheck} or a host's own
     * checks.
     *
     * @param  list<Check>  $checks
     */
    public function runWith(string $domain, array $checks): Report
    {
        $context = new DiagnosticContext(
            $domain,
            $this->resolver,
            $this->authoritative,
            new DnssecValidator($this->resolver),
            new PropagationChecker($this->resolver, $this->authoritative),
        );

        $findings = [];

        foreach ($checks as $check) {
            try {
                $results = $check->run($context);
            } catch (Throwable $failure) {
                $findings[] = Finding::error(
                    'Diagnostics',
                    'check.failed',
                    $check::class.' failed to run: '.$failure->getMessage(),
                    ['check' => $check::class],
                );

                continue;
            }

            foreach ($results as $finding) {
                $findings[] = $finding;
            }
        }

        return new Report($findings);
    }

    /**
     * The v1 catalog run for every domain, in report order.
     *
     * @return list<Check>
     */
    public static function defaultChecks(): array
    {
        return [
            new DelegationCheck,
            new NameserverCheck,
            new SoaCheck,
            new MxCheck,
            new SpfCheck,
            new DmarcCheck,
            new CaaCheck,
            new DnssecCheck,
            new PropagationCheck,
        ];
    }
}
