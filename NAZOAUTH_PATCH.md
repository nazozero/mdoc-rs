# NazoAuth integration

The maintained package is now `nazo-mdoc`. Its production migration baseline,
immutable dependency pinning, removed legacy features and host security
responsibilities are documented in [docs/migration.md](docs/migration.md).

The legacy `nazoauth/patched-rustcrypto` revision
`9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc` remains available for old consumers.
The old TSP dependency is not part of the new package's feature graph.
