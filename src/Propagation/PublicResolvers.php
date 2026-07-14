<?php

declare(strict_types=1);

namespace Cbox\Dns\Propagation;

/**
 * A registry of well-known public recursive resolvers, as named {@see PublicResolver}
 * value objects, so a propagation report can read "Google Public DNS ✓ /
 * Cloudflare ✓ / Quad9 pending" instead of bare IPs.
 *
 * IMPORTANT — what this registry does and does NOT give you. Polling many of these
 * from a single host is a CACHE-DIVERSITY signal: it shows whether independent
 * recursive operators have each refreshed their cache for a name. It is NOT true
 * global geographic propagation. Every major provider here (Google, Cloudflare,
 * Quad9, OpenDNS, …) is anycast, so from one host you always reach the nearest PoP
 * — you sample operators, not locations. The reliable propagation signal remains
 * the authoritative-vs-recursive diff that {@see PropagationChecker} computes.
 *
 * Geo-distributed vantage points (regional DoH probes exiting from multiple
 * regions) are a documented non-goal here — see the module roadmap — not a claim
 * this registry makes.
 */
class PublicResolvers
{
    /**
     * Every named public resolver known to the registry.
     *
     * @return list<PublicResolver>
     */
    public static function all(): array
    {
        return [
            new PublicResolver('google-primary', 'Google Public DNS', '8.8.8.8', 'Global (anycast)'),
            new PublicResolver('google-secondary', 'Google Public DNS', '8.8.4.4', 'Global (anycast)'),
            new PublicResolver('cloudflare-primary', 'Cloudflare', '1.1.1.1', 'Global (anycast)'),
            new PublicResolver('cloudflare-secondary', 'Cloudflare', '1.0.0.1', 'Global (anycast)'),
            new PublicResolver('quad9', 'Quad9', '9.9.9.9', 'Global (anycast)'),
            new PublicResolver('opendns-primary', 'OpenDNS', '208.67.222.222', 'Global (anycast)'),
            new PublicResolver('opendns-secondary', 'OpenDNS', '208.67.220.220', 'Global (anycast)'),
            new PublicResolver('level3-primary', 'Level3', '4.2.2.1', 'Global (anycast)'),
            new PublicResolver('level3-secondary', 'Level3', '4.2.2.2', 'Global (anycast)'),
            new PublicResolver('verisign', 'Verisign Public DNS', '64.6.64.6', 'Global (anycast)'),
            new PublicResolver('adguard', 'AdGuard DNS', '94.140.14.14', 'Global (anycast)'),
            new PublicResolver('dns-watch', 'DNS.Watch', '84.200.69.80', 'Germany'),
            new PublicResolver('neustar', 'Neustar UltraDNS', '156.154.70.1', 'Global (anycast)'),
            new PublicResolver('yandex', 'Yandex DNS', '77.88.8.8', 'Russia'),
            new PublicResolver('comodo', 'Comodo Secure DNS', '8.26.56.26', 'Global (anycast)'),
        ];
    }

    /**
     * The lean default panel {@see PropagationChecker} polls when no wider set is
     * requested — one entry per major operator, kept small so a check stays fast.
     *
     * @return list<PublicResolver>
     */
    public static function default(): array
    {
        return [
            new PublicResolver('google-primary', 'Google Public DNS', '8.8.8.8', 'Global (anycast)'),
            new PublicResolver('google-secondary', 'Google Public DNS', '8.8.4.4', 'Global (anycast)'),
            new PublicResolver('cloudflare-primary', 'Cloudflare', '1.1.1.1', 'Global (anycast)'),
            new PublicResolver('cloudflare-secondary', 'Cloudflare', '1.0.0.1', 'Global (anycast)'),
            new PublicResolver('quad9', 'Quad9', '9.9.9.9', 'Global (anycast)'),
            new PublicResolver('opendns-primary', 'OpenDNS', '208.67.222.222', 'Global (anycast)'),
        ];
    }
}
