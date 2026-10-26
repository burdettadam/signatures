# Maintained ECDSA verification fork

Upstream: https://github.com/RustCrypto/signatures

Fork: https://github.com/burdettadam/signatures

The maintained default branch is `master`. Keep accepted downstream fixes on
that branch; retain their commits when integrating upstream changes. Do not
replace this branch with an upstream mirror or force-push away downstream work.
No upstream PR is currently authorized.

## Downstream patch

Based on upstream `7b8bdcde8917a9db5775e689e25c91adb784492a`:

- `6867a48f17cfd45272ba58ccd50667b2f44b8d3a` separates ECDSA public verification
  from signing. `verifying` excludes RFC6979 and signing APIs; `signing` enables
  both capabilities; existing `algorithm` remains a compatibility alias.
- `acef2d671fea0289b6680d92a54e4f430d5c8d3f` uses the RFC public SEC1 key directly
  in the verification/recovery test, without deriving it from a private scalar.

No ECDSA arithmetic is changed. This Git fork is not a crates.io publication or
proof that downstream packages have adopted it. Consumers must pin an immutable
reviewed revision and resolve a single compatible ECDSA source for curve crates.

## Upstream updates

Fetch upstream separately, inspect its changes against the recorded base, and
merge selected updates on a review branch. Preserve the patch and its public
feature contract. Verify the exact candidate before advancing `master`; keep
the previous downstream checkpoint reachable. Update this file when the base,
patch, or supported feature contract changes. Do not automatically reset the
fork to upstream or change consumer pins as part of synchronization.

The local checkout uses `origin` for upstream fetching and `fork` for this fork;
its default push remote is `fork`, and local `master` tracks `fork/master`.

Run the focused feature checks after source changes (Rust 1.95 was used for the
initial patch):

```sh
cargo test --locked -p ecdsa --no-default-features --features verifying --test verifying_only
cargo test --locked -p ecdsa --no-default-features --features signing --test verifying_only
cargo test --locked -p ecdsa --no-default-features --features algorithm --test verifying_only
```

Also inspect the production verifier-only dependency graph for absent
`rfc6979`, `signing`, and `algorithm`, and confirm a fresh verifier-only consumer
cannot import `ecdsa::SigningKey`. Workspace test dependencies are not production
feature-closure evidence. Preserve failures and resolve concrete regressions
before updating consumer revisions.
