---
title: Templates
weight: 48
description: The Template and TemplateRecord model, the host rule, variables and built-ins, groups, expanding a template into a RecordSet, and how RecordSetCheck compares records.
---

# Templates

A template is a JSON document that names your service and lists the records it
needs. It is published in the public
[Domain Connect Templates repository](https://github.com/Domain-Connect/Templates),
where it is reviewed, and DNS providers onboard it from there. Keep the same file in
your application and load it with `Template::fromJson()`, so the template you build
URLs and check records with is the one you published.

```json
{
  "providerId": "example.com",
  "providerName": "Example",
  "serviceId": "mail",
  "serviceName": "Example mail",
  "version": 1,
  "syncPubKeyDomain": "example.com",
  "syncRedirectDomain": "app.example.com",
  "records": [
    { "groupId": "sending", "type": "MX",   "host": "send", "pointsTo": "%mx%", "priority": 10, "ttl": 3600 },
    { "groupId": "sending", "type": "SPFM", "host": "send", "spfRules": "include:mail.example.com" },
    { "groupId": "sending", "type": "TXT",  "host": "ex._domainkey", "data": "p=%dkim%", "ttl": 3600, "txtConflictMatchingMode": "All" },
    { "groupId": "dmarc",   "type": "TXT",  "host": "_dmarc", "data": "v=DMARC1; p=quarantine", "ttl": 3600,
      "txtConflictMatchingMode": "Prefix", "txtConflictMatchingPrefix": "v=DMARC1", "essential": "OnApply" }
  ]
}
```

## The model

`Template` holds `providerId`, `providerName`, `serviceId`, `serviceName`, `version`,
`records`, and the optional `syncPubKeyDomain`, `syncRedirectDomain`, `syncBlock`,
`logoUrl`, `description` and `variableDescription`. `Template::fromJson()` /
`fromArray()` read it, `toArray()` writes it back; a missing or wrongly typed field,
or an unknown record type, throws `InvalidTemplate`.

`TemplateRecord` holds one record: `type` (`TemplateRecordType`: `A`, `AAAA`,
`CNAME`, `NS`, `TXT`, `MX`, `SRV`, `SPFM`, `APEXCNAME`), `host`, and the value field
for its type — `data` for `TXT`, `spfRules` for `SPFM`, `pointsTo` for the rest —
plus `ttl`, `priority`, `groupId`, `essential` (`Always` or `OnApply`),
`txtConflictMatchingMode` (`None`, `All`, `Prefix`) and `txtConflictMatchingPrefix`.
`SPFM` and `APEXCNAME` are Domain Connect pseudo-types: `SPFM` merges SPF terms into
the zone's one SPF record, `APEXCNAME` is a CNAME-like record at the apex.

`essential` and the TXT conflict fields tell the DNS provider how to apply the
record. They are kept on the model, but the record check below does not use them.

## Hosts

A record's `host` is relative to the zone the template is applied to — the apex, or
`host.apex` when the request has a host:

| `host` | Applied to `acme.com` | Applied to `mail.acme.com` |
| --- | --- | --- |
| `@` or empty | `acme.com` | `mail.acme.com` |
| `send` | `send.acme.com` | `send.mail.acme.com` |
| `ex.other.com.` (trailing dot) | `ex.other.com` | `ex.other.com` |

A trailing dot makes the host absolute; it is used as written. An `APEXCNAME` record
always lands on `@`. Names are lowercased and carry no trailing dot.

## Variables

A value written `%name%` is a variable (`[A-Za-z0-9_]`). Three are **built in** and
filled from the zone, never by you:

| Variable | Value for `mail.acme.com` |
| --- | --- |
| `%domain%` | `acme.com` |
| `%host%` | `mail` |
| `%fqdn%` | `mail.acme.com` |

Every other variable must be supplied by the caller. `Template::variables()` lists
them in order of first use, without the built-ins; that is the list `applyUrl()`
requires values for. Variables may appear in `host`, `pointsTo`, `data` and
`spfRules`. A substituted value is never scanned again, so a value that itself
contains `%...%` is inserted as is.

## Groups

`groupId` splits a template into parts the customer can apply separately — in the
example, `sending` always and `dmarc` only when the domain has no DMARC policy yet.
`Template::groupIds()` lists them. Pass group ids on `ApplyRequest` (sent as
`groupId=sending,dmarc`) and to `recordSet()`; an id the template does not define is
refused. An empty list means every record. With a non-empty list, a record without a
`groupId` is left out.

## The record set

`DomainConnect::recordSet(Template $template, Zone $zone, array $variables, array $groupIds = []): RecordSet`
(or `RecordSet::fromTemplate()`) expands a template into the records the zone should
carry once applied: a list of `ExpectedRecord` (`type`, `name`, `value`, `priority`,
`ttl`, `groupId`), with every variable substituted and every name fully qualified.
`CNAME`, `NS`, `MX` and `APEXCNAME` targets are lowercased and lose their trailing
dot; for `SPFM` the value is the SPF terms.

Use it for anything that needs "the records for this customer": a table of records
to add by hand when the DNS provider does not support Domain Connect, and the check
below.

It throws `InvalidApplyRequest` for an unknown variable, an unknown group, a variable
a kept record needs but was not given, a record missing its value field, and any
`SRV` record (not supported).

## Checking the records

`DomainConnect::check(RecordSet $set): Report` runs `RecordSetCheck` through the
[diagnostics engine](../diagnostics/_index.md). It reads each expected record from
the zone's **authoritative nameservers** and returns the usual `Report` with one
`Finding` per record, in record-set order, category `DomainConnect`:

| Check id | Severity | When |
| --- | --- | --- |
| `domain-connect.present` | info | A live record matches. |
| `domain-connect.missing` | error | No record of that type at the name, or the lookup failed. |
| `domain-connect.mismatch` | error | Records exist but none matches. |

Each finding's context carries `name`, `type`, `expected` and the `live` values.
One matching record among several is enough. TTLs are not compared.

| Type | Looked up as | Matches when |
| --- | --- | --- |
| `A`, `AAAA` | `A`, `AAAA` | The address string is equal. |
| `CNAME`, `NS` | `CNAME`, `NS` | The target is equal, ignoring case and a trailing dot. |
| `APEXCNAME` | `CNAME` at the apex | As `CNAME`. A provider that flattens the apex CNAME into addresses will show it as missing. |
| `MX` | `MX` | Priority and target (case and trailing dot ignored) are equal. |
| `TXT` | `TXT` | The value is equal after trimming; multi-string TXT records are joined first. |
| `SPFM` | `TXT` | A record starts with `v=spf1` and contains **every** whitespace-separated term of `spfRules` as an exact term. `v=spf1 include:mail.example.com ~all` matches `include:mail.example.com`; `include:mail.example.com.evil` does not. |

`check()` only tells you what DNS says right now. A DNS provider's "success" redirect
can come before the records are served, so check again later rather than treating a
first `missing` as failure.
