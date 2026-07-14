---
title: Core concepts
weight: 20
description: The resolver contract, the three transports, authoritative reads, domain verification, propagation, and the overall architecture.
---

# Core concepts

The library is small and layered. One contract, three transports, and a handful of
capabilities composed on top.

- **[Architecture](architecture.md)** — the contract, the facade, and how the
  layers compose.
- **[Resolvers](resolvers.md)** — the socket, DoH, and authoritative transports.
- **[Domain verification](domain-verification.md)** — authoritative TXT ownership
  checks.
- **[Propagation](propagation.md)** — authoritative-vs-recursive comparison and its
  honest scope.
