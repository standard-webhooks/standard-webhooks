# Changelog

All notable changes to the Standard Webhooks specification and libraries are
documented here.

## 1.3.0

Starting with this release, all libraries share one version number and are
released together from a single `vX.Y.Z` tag. The changes below are relative
to each library's previous release.

### Specification

- New [extensions](spec/standard-webhooks.md#extensions) section: optional
  additions to the specification. Implementations don't need to support them
  to be compatible, but those that do should follow them exactly.
- New extension: [webhook endpoint verification (WEV)](spec/extensions/endpoint-verification.md).
  A producer sends a random challenge in the `webhook-challenge` header, and the
  endpoint proves it has opted in and holds the correct key by responding with
  a `webhook-challenge-response` header derived from the endpoint's key. (#344)

### All libraries

- Added webhook endpoint verification: a function for consumers to calculate
  the response to a challenge, and one for producers to verify that response.
  See each library's README. (#344)
- Fixed parsing of the `webhook-signature` header in `verify`. Every library
  now compares each space-delimited entry against the full expected versioned
  signature (e.g. `v1,<sig>`) in constant time. Previously, depending on the
  library: a malformed entry made verification fail even when a later
  signature was valid (Python, Ruby, C#, PHP); entries with extra commas such
  as `v1,<sig>,junk` were accepted (JavaScript, Go, Java); or only the last
  signature was checked and its version was ignored (Elixir). (#343)

### C#

Note: we allowed some breaking changes here since it's the first published
release of this library.

- **Breaking:** the package is now named `StandardWebhooks.StandardWebhooks`.
- **Breaking:** removed the unused dependencies on
  `Microsoft.Extensions.Logging.Abstractions`, `Newtonsoft.Json`, `Polly` and
  `System.ComponentModel.Annotations`. Reference them directly if you relied
  on them transitively. (#362)
- The package now targets only `netstandard2.0` instead of `net5.0`. It runs on
  the same runtimes. (#362)
- Empty signing secrets are now rejected with `EmptyWebhookSecretException`.
  (#286)

### Elixir

Note: we allowed some breaking changes here since it's the first published
release of this library.

- **Breaking:** `verify/3` and `sign/4` now take the raw request body (a
  binary) instead of a decoded map, and sign it byte for byte like the other
  libraries. Re-encoding a map often didn't reproduce the bytes that were
  sent, so verification failed. Passing a map now raises `ArgumentError`. The
  README shows how to keep the raw body when using `Plug.Parsers`. (#371)
- Fixed `whsec_`-prefixed secrets being base64-decoded twice, which produced
  wrong signatures. (#342)
- Empty signing secrets are now rejected. (#286)
- Removed the unused `jason` dependency. (#371)
- Fixed the Hex package build and added the license file to the package.
  (#385)

### Go

- Empty signing secrets are now rejected. (#286)

### Java

- Added the license file to the package. (#341)
- Updated the Maven publishing plugin. (#318)

### JavaScript

- `sign` and `verify` now handle binary payloads byte for byte. A `Buffer` or
  `Uint8Array` is signed as is, so bodies that aren't valid UTF-8 (gzip,
  protobuf, ...) verify correctly. Before, `Buffer` payloads were decoded as
  UTF-8 first, which corrupted them, and `Uint8Array` was rejected. (#348)

### PHP

- Empty signing secrets are now rejected with `EmptyWebhookSecretException`.
  (#286)
- Fixed `Webhook::fromRaw()`, which always threw after the empty secret check
  was added. (#354)

### Python

- **Breaking:** dropped support for Python 3.9. (#355)
- `sign` and `verify` now accept `bytes`, `bytearray` and byte `memoryview`
  payloads and sign them byte for byte. Before, `verify` raised
  `UnicodeDecodeError` on bodies that aren't valid UTF-8, and `sign` silently
  produced a wrong signature for `bytes`. (#348)
- Fixed `sign` for timezone-aware `datetime` timestamps that aren't in UTC,
  which produced signatures that never verified. Naive datetimes are still
  treated as UTC. (#334)
- Added the license file and more metadata to the PyPI package. (#302, #303)

### Ruby

- Empty signing secrets are now rejected with `EmptyWebhookSecretError`.
  (#286)

### Rust

- `Webhook` and `WebhookError` now implement `Clone`, `PartialEq` and `Eq`.
  `Webhook`'s `Debug` output redacts the secret. (#241)
- Empty signing secrets are now rejected. (#286)
- Updated the `base64` dependency. (#363)
