<?php

declare(strict_types=1);

namespace Cbox\Dns\Testing;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Resolvers\AuthoritativeResolver;

/**
 * The dogfooded testing seam. Compose this trait into a `TestCase` (or use it
 * ad-hoc) to spin up a {@see FakeResolver}, wire it into a {@see Dns} facade, and
 * stub a zone's authoritative NS chain without repeating the boilerplate in every
 * test.
 *
 * The whole library resolves through the one {@see Resolver}
 * seam, so a faked resolver drives lookups, verification, propagation, diagnostics,
 * and the DNSSEC chain walk offline.
 */
trait InteractsWithDns
{
    protected ?FakeResolver $fakeResolver = null;

    /**
     * A shared {@see FakeResolver} for the current test.
     */
    protected function fakeDns(): FakeResolver
    {
        return $this->fakeResolver ??= new FakeResolver;
    }

    /**
     * A {@see Dns} facade backed by the fake resolver. Non-public nameserver IPs are
     * allowed by default so a test can use documentation/LAN addresses for stubbed
     * authoritative servers.
     */
    protected function fakeDnsFacade(string $challengePrefix = '_cbox-challenge'): Dns
    {
        return new Dns($this->fakeDns(), $challengePrefix, allowNonPublicNameservers: true);
    }

    /**
     * An {@see AuthoritativeResolver} over the fake resolver (non-public NS IPs
     * allowed) — the collaborator the verifier and propagation checker compose.
     */
    protected function fakeAuthoritative(): AuthoritativeResolver
    {
        return new AuthoritativeResolver($this->fakeDns(), allowNonPublicNameservers: true);
    }

    /**
     * Stub a zone's authoritative delegation: its NS record and each nameserver's
     * A address, so {@see AuthoritativeResolver} can discover a server to query.
     *
     * @param  array<string, string>  $nameservers  NS hostname => its A address
     */
    protected function stubZone(string $zone, array $nameservers): FakeResolver
    {
        $fake = $this->fakeDns();
        $fake->stub($zone, RecordType::NS, array_keys($nameservers));

        foreach ($nameservers as $host => $address) {
            $fake->stub($host, RecordType::A, [$address]);
        }

        return $fake;
    }
}
