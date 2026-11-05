# ONREZA embedded library fork

This branch preserves KumoMTA ancestry and starts at upstream commit
[`e61bc0844a9d93078bd3f78a7050584ca4cafd01`](https://github.com/KumoCorp/kumomta/commit/e61bc0844a9d93078bd3f78a7050584ca4cafd01).
It supports only these Cargo workspace members:

- `rfc5321`, `mailparsing`, `kumo-dkim`, `dns-resolver`, `mta-sts`
- `kumo-tls-helper`, `lruttl`, `kumo-prometheus`, `kumo-address`
- `kumo-wrap`, `duration-serde`, `nom-utils`

Upstream daemon, spool, scheduler, configuration, and deployment files remain
in the repository for history. They are outside this workspace and are not
qualified by its checks. No application or database implementation is included
in the fork changes. The upstream GitHub Actions workflows are disabled.

## Changes from upstream

The library sources, tests, and fixtures retain the embedded changes:

- detach the cache from the daemon memory monitor while preserving bounded
  capacity, TTL maintenance, and explicit purge;
- move `ResolvedAddress` into the DNS library without changing its representation;
- expose the asynchronous SMTP DATA barrier, negotiated capabilities, SMTPUTF8
  header negotiation, and validated DSN envelope parameters;
- accept SMTP RCPT 251 and close refused envelopes without sending empty DATA
  outside the barrier; exclude raw SMTP lines and responses from tracing;
- enforce the TLS floor and DNSSEC proof checks, and support explicit DNSKEY
  trust anchors;
- bound MTA-STS retrieval and public dual-stack HTTPS addresses, and expose the
  policy-document cache interface for application-owned durable storage;
- retain strict 1-to-10-digit MTA-STS `max_age` parsing and checked expiry
  arithmetic instead of clamping the parsed policy value;
- make the existing metric-declaration documentation example self-contained so
  its doctest imports the macros and defines its label key.

The root manifest limits the workspace to these libraries. Hickory packages use
one pinned ONREZA Git source, so DNS record types have a single Cargo identity.
DANE support uses the OpenSSL 0.10.82 bindings with the carried KumoCorp DANE patch.
Cargo consumers must repeat root-level Cargo patches in their own workspace;
Cargo does not inherit dependency patches from Git dependencies.

The Apache-2.0 root [LICENSE](LICENSE) is copied unchanged into the eleven
Apache-licensed library package directories so Cargo vendoring preserves it.
`kumo-dkim` retains its separate [MIT license](crates/dkim/LICENSE).
Other upstream copyright and license notices remain intact.

## Checks

Run the supported workspace tests with the committed dependency resolution:

```sh
cargo test --workspace --locked
cargo check --workspace --all-targets --locked
```

These checks include the carried library tests and fixtures. They do not qualify
a consuming application's runtime or the upstream daemon. Live DNS tests and
optional Lua or libunbound features require explicit additional qualification.
