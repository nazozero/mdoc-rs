# NazoAuth dependency patch

This branch builds on c5d460cfd667324e51e590e8ecbbdb21f63bbdbe and retains the
COSE 0.4 and borrowed-transcript contracts. It upgrades RustCrypto curves to
remove the production dependency on crypto-bigint 0.5.5 (RUSTSEC-2026-0387).

The default `tsp` feature still pulls `tsp-ltv` and its vulnerable
crypto-bigint 0.5.5 dependency. NazoAuth disables default features and enables
only `issue`; this patch does not claim to repair the TSP dependency chain.

TODO: retire this branch when a maintained release both uses a non-yanked,
patched crypto-bigint and preserves the COSE and borrowed-transcript contracts,
as verified by NazoAuth's credential tests.
