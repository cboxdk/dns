<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolution;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\Support\Hostname;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Follows a name's CNAME chain to its answer (RFC 1034 §3.6.2), recording every hop
 * for traceability. This is an EXPLICIT opt-in: {@see Resolver::query()}
 * returns whatever the server sent, and a recursive resolver already flattens
 * CNAMEs server-side; this follower is what makes the chain visible, and it also
 * chases the chain itself when the answering server did not (an authoritative
 * query, which returns only the CNAME because the server is not authoritative for
 * the target).
 *
 * Loop-safe: a name is never queried twice, and a CNAME that points back into the
 * chain stops the resolution with a reason rather than spinning. The depth is
 * bounded by {@see self::MAX_DEPTH}.
 */
class CnameResolver
{
    /** Hard cap on CNAME chain length. */
    public const int MAX_DEPTH = 16;

    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
    ) {}

    /**
     * Resolve `$host` for `$type`, following CNAMEs and recording the chain.
     */
    public function resolve(string $host, RecordType $type): ResolvedChain
    {
        $host = strtolower(Hostname::toAscii($host));

        $chain = [];
        $visited = [];
        $current = $host;

        for ($depth = 0; $depth < self::MAX_DEPTH; $depth++) {
            if (isset($visited[$current])) {
                return new ResolvedChain($host, $type, $chain, [], false, "CNAME loop at {$current}");
            }

            $visited[$current] = true;

            try {
                $response = $this->resolver->query($current, $type);
            } catch (DnsException $e) {
                return new ResolvedChain($host, $type, $chain, [], false, $e->getMessage());
            }

            // A recursive resolver returns the intermediate CNAMEs plus the final
            // answer in one response; follow the CNAME links present here from the
            // current name, extending the chain (with an inner loop guard). Names
            // consumed within the response are marked visited too, so loop detection
            // does not have to fall back to MAX_DEPTH.
            $next = $this->followWithin($response, $current, $chain, $visited);

            if ($next === false) {
                return new ResolvedChain($host, $type, $chain, [], false, "CNAME loop at {$current}");
            }

            if ($response->records !== []) {
                return new ResolvedChain($host, $type, $chain, $response->records, true);
            }

            // No record of the requested type. If a CNAME advanced us to a name we
            // have not queried, re-query it (the authoritative, not-flattened case).
            if ($next !== $current && ! isset($visited[$next])) {
                $current = $next;

                continue;
            }

            $reason = $response->isNxDomain()
                ? "{$current} does not exist (NXDOMAIN)"
                : "no {$type->value} record for {$current}".($next !== $current ? ' (CNAME target unresolved)' : '');

            return new ResolvedChain($host, $type, $chain, [], false, $reason);
        }

        return new ResolvedChain($host, $type, $chain, [], false, 'CNAME chain exceeded '.self::MAX_DEPTH.' hops');
    }

    /**
     * Follow the CNAME links in one response starting from `$name`, appending each
     * to `$chain`. Returns the final name reached, or false on a loop within the
     * response.
     *
     * @param  list<CnameHop>  $chain
     * @param  array<string, bool>  $visited
     */
    private function followWithin(DnsResponse $response, string $name, array &$chain, array &$visited): string|false
    {
        $seen = [$name => true];

        while (true) {
            $cname = null;

            foreach ($response->answerOfType(RecordType::CNAME) as $record) {
                if (strtolower(rtrim($record->name, '.')) === $name) {
                    $cname = strtolower(rtrim($record->value, '.'));

                    break;
                }
            }

            if ($cname === null) {
                return $name; // the frontier; the outer loop marks it visited when it queries it
            }

            $chain[] = new CnameHop($name, $cname);

            if (isset($seen[$cname]) || isset($visited[$cname])) {
                return false; // a CNAME pointing back into the chain
            }

            $visited[$name] = true; // this intermediate is consumed and will not be queried
            $seen[$cname] = true;
            $name = $cname;
        }
    }
}
