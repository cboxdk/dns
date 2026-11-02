---
title: Domain Connect
weight: 45
description: Set up DNS records through the customer's own DNS provider with Domain Connect — discover, build a signed apply URL, check the result.
---

# Domain Connect

[Domain Connect](https://www.domainconnect.org/) is an open standard that lets a
service ask a customer's DNS provider to add a fixed set of records — a
*template* — to the customer's domain. The customer clicks a link, signs in at their
DNS provider (Cloudflare, GoDaddy, IONOS, …), approves the change, and is sent back.
Nobody copies a DKIM key into a web form by hand.

The `Cbox\Dns\DomainConnect` module is the service-provider side of that exchange.
It covers the **synchronous flow**: discovery, the signed apply URL, reading the
redirect back, and checking the records against authoritative DNS afterwards.

## Mental model

A template is published once, in the public
[Domain Connect Templates repository](https://github.com/Domain-Connect/Templates),
and DNS providers onboard it from there. Per customer domain you then make three
calls: **discover** whether the domain's DNS provider speaks Domain Connect and knows
your template, **build the apply URL** (signed with your private key) and send the
customer to it, and **check** the zone afterwards. The DNS provider's redirect only
says the customer did not cancel; whether the records are live is something only DNS
can answer, so the check reads them from the zone's authoritative nameservers.

## The three calls

```php
use Cbox\Dns\Dns;
use Cbox\Dns\DomainConnect\ApplyRequest;
use Cbox\Dns\DomainConnect\Signers\OpenSslRs256Signer;
use Cbox\Dns\DomainConnect\Template;

$dc = (new Dns)->domainConnect(new OpenSslRs256Signer($privateKeyPem));
$template = Template::fromJson(file_get_contents('example.com.mail.json'));

// 1. Discover: does acme.com's DNS provider speak Domain Connect and know the template?
$discovery = $dc->discover('acme.com', $template);

if ($discovery->isAvailable() && $discovery->supportsTemplate()) {
    // 2. Send the customer to their DNS provider with a signed apply URL.
    $url = $dc->applyUrl(new ApplyRequest(
        template: $template,
        zone: $discovery->zone,
        variables: ['token' => $token],
        redirectUri: 'https://app.example.com/domain-connect/callback',
        state: $state,
    ), $discovery->settings);
}

// On the redirect back: the provider's answer (state validation is yours).
$outcome = $dc->outcome($_GET);
$outcome->succeeded();   // false when the provider sent `error` (e.g. access_denied)

// 3. Check: are the records published at the zone's authoritative nameservers?
$report = $dc->check($dc->recordSet($template, $discovery->zone, ['token' => $token]));
$report->passed();
```

`Dns::domainConnect(Signer $signer, ?Transport $transport = null, string $keyHost = '_dcpubkeyv1')`
wires the module over the facade's resolver. The default transport is
`StreamTransport` (PHP streams, 5-second timeout, no redirects followed). Discovery
lookups (`SOA`, `_domainconnect` TXT, the provider's addresses) go through that
resolver; `check()` reads from the zone's authoritative nameservers.

## Pages

- **[Discovery](discovery.md)** — the `_domainconnect` TXT record, the settings
  document, the template support check, and how the HTTPS requests are guarded.
- **[Signing](signing.md)** — the RS256 signature, the `sig` and `key` parameters,
  publishing the public key, and rotating it.
- **[Templates](templates.md)** — the template model, hosts, variables, groups, the
  expanded record set, and how the check compares records.
- **[Testing](testing.md)** — `InteractsWithDomainConnect`, `FakeTransport` and
  `FakeSigner`, with an end-to-end example.

## Scope

- **Synchronous flow only.** The asynchronous (OAuth) flow, where a service provider
  holds a token and applies templates through the provider's API, is not
  implemented.
- **SRV records are not supported.** A template with an SRV record cannot be
  expanded into a record set, so it cannot be checked.
- The module does not publish templates, store discovery results, or validate the
  `state` you get back — those belong to the application.
