<?php

declare(strict_types=1);

namespace Cbox\Dns;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Diagnostics\Diagnostics;
use Cbox\Dns\Diagnostics\Report;
use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Propagation\PropagationReport;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\ValueObjects\DnsResponse;
use Cbox\Dns\Verification\DomainVerifier;

/**
 * The front door: a thin facade wiring the resolver, authoritative reader, domain
 * verifier, and propagation checker together so the common tasks are one call.
 * Everything it composes is public, so a host can reach past it when it needs to.
 *
 * DNSSEC chain validation is a separate module ({@see Dnssec}). It plugs
 * in here without a refactor: it composes {@see self::authoritative()} (or the raw
 * {@see self::resolver()}) to fetch DNSKEY/DS/RRSIG records and validates the chain
 * with a vetted crypto primitive. This facade deliberately leaves that seam open
 * rather than hard-coding DNSSEC away.
 */
final class Dns
{
    private readonly AuthoritativeResolver $authoritative;

    private readonly DomainVerifier $verifier;

    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
    ) {
        $this->authoritative = new AuthoritativeResolver($this->resolver);
        $this->verifier = new DomainVerifier($this->authoritative);
    }

    /**
     * Look a record up through the underlying resolver (recursive by default).
     */
    public function lookup(string $host, RecordType $type): DnsResponse
    {
        return $this->resolver->query($host, $type);
    }

    /**
     * Verify domain ownership by reading the challenge TXT authoritatively.
     */
    public function verifyDomain(string $domain, string $token): bool
    {
        return $this->verifier->verify($domain, $token);
    }

    /**
     * The host at which a domain's verification TXT record must be published.
     */
    public function challengeHost(string $domain): string
    {
        return $this->verifier->challengeHost($domain);
    }

    /**
     * Compare a host's authoritative record set against the public resolver panel.
     */
    public function checkPropagation(string $host, RecordType $type, string $zone): PropagationReport
    {
        return (new PropagationChecker($this->resolver, $this->authoritative))->check($host, $type, $zone);
    }

    /**
     * Run the intoDNS/MxToolbox-style diagnostics catalog against a domain,
     * returning a structured {@see Report} of delegation, SOA, mail, SPF/DMARC,
     * CAA, DNSSEC, and propagation findings — all resolved through this facade's
     * resolver.
     */
    public function diagnose(string $domain): Report
    {
        return (new Diagnostics($this->resolver))->run($domain);
    }

    /**
     * The underlying resolver — the seam a DNSSEC validator (or any extension)
     * composes to fetch records itself.
     */
    public function resolver(): Resolver
    {
        return $this->resolver;
    }

    /**
     * The authoritative reader — the cache-bypassing seam DNSSEC validation and
     * ownership checks build on.
     */
    public function authoritative(): AuthoritativeResolver
    {
        return $this->authoritative;
    }

    /**
     * The DNSSEC chain validator, anchored on the IANA root trust anchors and
     * fetching DNSKEY/DS/RRSIG through this facade's resolver. Trust comes from
     * validating the signatures, not from the transport.
     */
    public function dnssec(): DnssecValidator
    {
        return new DnssecValidator($this->resolver);
    }
}
