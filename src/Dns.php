<?php

declare(strict_types=1);

namespace Cbox\Dns;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Diagnostics\Checks\DkimCheck;
use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\Diagnostics;
use Cbox\Dns\Diagnostics\Report;
use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Propagation\PropagationReport;
use Cbox\Dns\Resolution\CnameResolver;
use Cbox\Dns\Resolution\ResolvedChain;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\Spf\SpfEvaluation;
use Cbox\Dns\Spf\SpfResolver;
use Cbox\Dns\Tracing\DelegationTrace;
use Cbox\Dns\Tracing\DelegationTracer;
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
class Dns
{
    private readonly AuthoritativeResolver $authoritative;

    private readonly DomainVerifier $verifier;

    /**
     * @param  string  $challengePrefix  the label used for ownership challenge TXT
     *                                   records (default `_cbox-challenge`)
     * @param  bool  $allowNonPublicNameservers  lift the SSRF address filter so
     *                                           authoritative reads may target
     *                                           LAN/reserved nameserver IPs (off by
     *                                           default — see {@see AuthoritativeResolver})
     */
    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
        string $challengePrefix = '_cbox-challenge',
        bool $allowNonPublicNameservers = false,
    ) {
        $this->authoritative = new AuthoritativeResolver($this->resolver, $allowNonPublicNameservers);
        $this->verifier = new DomainVerifier($this->authoritative, $challengePrefix);
    }

    /**
     * Look a record up through the underlying resolver (recursive by default).
     */
    public function lookup(string $host, RecordType $type): DnsResponse
    {
        return $this->resolver->query($host, $type);
    }

    /**
     * Look a record up, explicitly following the CNAME chain and returning it for
     * traceability (the hops, the canonical name, and the final answer). Loop-safe.
     */
    public function follow(string $host, RecordType $type): ResolvedChain
    {
        return (new CnameResolver($this->resolver))->resolve($host, $type);
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
     * Pass a custom `$publicNameservers` list to override the default panel.
     *
     * @param  list<string>|null  $publicNameservers
     */
    public function checkPropagation(string $host, RecordType $type, string $zone, ?array $publicNameservers = null): PropagationReport
    {
        $checker = $publicNameservers !== null
            ? new PropagationChecker($this->resolver, $this->authoritative, $publicNameservers)
            : new PropagationChecker($this->resolver, $this->authoritative);

        return $checker->check($host, $type, $zone);
    }

    /**
     * Compare against the FULL named public-resolver registry, labelling each
     * result with its provider (see {@see PropagationChecker::checkAcrossProviders()}).
     */
    public function checkPropagationAcrossProviders(string $host, RecordType $type, string $zone): PropagationReport
    {
        return (new PropagationChecker($this->resolver, $this->authoritative))->checkAcrossProviders($host, $type, $zone);
    }

    /**
     * Expand a domain's SPF policy (RFC 7208) into the complete authorized-sender
     * tree — following `include:` / `redirect=` and expanding `a` / `mx` — with the
     * RFC lookup limit and loop protection enforced. Read `->allIp4()` / `->allIp6()`
     * for the flattened endpoint list, or walk the tree for traceability.
     */
    public function spf(string $domain): SpfEvaluation
    {
        return (new SpfResolver($this->resolver))->resolve($domain);
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
     * Run a specific list of diagnostic checks (e.g. a selector-scoped
     * {@see DkimCheck}, or a host's own checks) instead
     * of the default catalog.
     *
     * @param  list<Check>  $checks
     */
    public function diagnoseWith(string $domain, array $checks): Report
    {
        return (new Diagnostics($this->resolver))->runWith($domain, $checks);
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

    /**
     * Trace a name's delegation from the root down (`dig +trace`-style): every zone
     * cut, the server that answered it, and the referral to the child zone.
     */
    public function trace(string $name, RecordType $type = RecordType::NS): DelegationTrace
    {
        return (new DelegationTracer($this->resolver))->trace($name, $type);
    }

    /**
     * Trace the reverse (in-addr.arpa / ip6.arpa) delegation of an IP address — the
     * chain that carries CIDR / reverse-zone delegation.
     */
    public function traceReverse(string $ip): DelegationTrace
    {
        return (new DelegationTracer($this->resolver))->traceReverse($ip);
    }
}
