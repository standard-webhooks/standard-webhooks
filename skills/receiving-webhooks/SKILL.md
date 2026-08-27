---
name: receiving-webhooks
description: >-
  General guidelines for building a robust webhook receiver/handler:
  verifying signatures, raw-body access, replay protection, async processing,
  retries and endpoint auto-disabling. Use whenever you write, review,
  or debug a handler that consumes incoming webhooks from any provider.
---

# Receiving Webhooks

A webhook is just an HTTP POST from a source you don't control. Treat every
request as untrusted until its signature is verified. These guidelines apply to
any handler consuming webhooks, regardless of which provider or platform sends
them.

Header names, secret formats, and tolerances vary by provider. The names below
follow the [Standard Webhooks](https://www.standardwebhooks.com) specification;
always confirm the exact header names, signing scheme, and replay window against
your provider's documentation before writing code.

## Standard Webhooks

[Standard Webhooks](https://www.standardwebhooks.com) is an open specification
plus reference libraries in most major languages for sending and verifying
webhooks securely and consistently. Instead of every provider inventing its own
header names and signing scheme, it defines a single, interoperable format.
When your provider supports it, prefer the official `standardwebhooks` library over hand-rolled
verification, it validates the signature, enforces the timestamp tolerance, and
guards against replay attacks for you. The examples below use it.

If your provider sends webhooks through [Svix](https://www.svix.com) (the
`svix-id`, `svix-timestamp`, and `svix-signature` headers are the tell), use the
official Svix SDK instead.

## The non-negotiables

1. **Verify the signature on every request.** An unverified webhook is an
   anonymous internet POST. Anyone who learns your URL can forge events. Only
   act on payloads that pass verification.
2. **Verify against the *raw* request body.** The signature is computed over the
   exact bytes sent. Any framework that parses JSON and re-stringifies it breaks
   verification. Read the unprocessed body.
3. **Return a `2xx` within seconds.** Anything else, including `3xx`
   redirects, is typically treated as a failure and retried. Push heavy work async.

## Handler shape

1. **Read the raw body.** Do not parse JSON before verification.
2. **Verify** the signature using the provider's official library (or its
   documented scheme), passing the signature headers and your signing secret. On
   failure, return `400`.
3. **Acknowledge fast.** Return `2xx` (e.g. `204`) immediately; do real work in
   a background job/queue if it can exceed a second or two.
4. **Branch on the payload** (event type) and process.

```ts
import { Webhook } from "standardwebhooks";

// rawBody must be the RAW request body (string/bytes), not parsed JSON.
// secret is the base64 signing secret for this endpoint.
const wh = new Webhook(secret);

let payload;
try {
  // Verifies the signature AND the timestamp tolerance; throws on failure.
  payload = wh.verify(rawBody, req.headers);
} catch (err) {
  return res.status(400).send(); // verification failed, reject
}
// payload is now trusted; enqueue and ack
return res.status(204).send();
```

Prefer the provider's official verification library when one exists: it validates
the signature **and** the timestamp tolerance and handles replay protection for
you, so you don't reimplement crypto by hand.

## Signature headers and the secret

Most providers send some combination of:

| Concept | Typical header | Purpose |
|--------|---------|---------|
| Message ID | `webhook-id` | Unique identifier for the message |
| Timestamp | `webhook-timestamp` | Send time, used for replay protection |
| Signature | `webhook-signature` | HMAC signature(s), often versioned |

- **Use the signing secret, not an API key.** The secret used to verify inbound
  webhooks is usually distinct from the API token you use to call the provider's
  management API.
- **Keep the secret server-side.** Never ship it in client bundles or commit it.

## Responding, retries, and auto-disable

- **Only `2xx` means success.** Every other code (often including `3xx`) is
  treated as a failure and retried, usually on an exponential-backoff schedule.
- **Respond within the provider's timeout** (commonly a few to ~15 seconds). If
  processing can take longer, ack first and work async.
- **Use `4xx` to reject bad/forged requests** (failed verification returns
  `400`); use `5xx`/timeouts only for genuine transient failures you want retried.
- **Endpoints often auto-disable** after sustained failure. Many providers notify
  you of this (e.g. via an operational/alert webhook or email). Keep your handler
  healthy to avoid silent disabling, and wire up failure notifications.

## Manual verification (only when no official library exists)

Prefer the provider's official library. If your language genuinely has none,
follow the provider's documented signing scheme exactly and **don't invent your
own**. The steps are:

1. **Extract the secret bytes.** The signing secret is prefixed with `whsec_`;
   strip the prefix and base64-decode the remainder to get the HMAC key.
2. **Read the signature headers.** Take `webhook-id`, `webhook-timestamp`, and
   `webhook-signature` from the request.
3. **Check the timestamp tolerance.** Reject if `webhook-timestamp` is too far
   from now (Standard Webhooks uses a 5-minute window) to guard against replay.
4. **Build the signed content** as `{id}.{timestamp}.{body}`, using the **raw**
   body bytes.
5. **Compute the HMAC-SHA256** of the signed content with the decoded secret and
   base64-encode it.
6. **Compare in constant time.** `webhook-signature` is a space-separated list of
   `v1,<sig>` entries; pass if your computed signature matches any of them. Use a
   constant-time comparison, never `==`.

## Verification traps (debugging a failing handler)

- **Body parsed before verification.** Re-stringification changes the bytes. Use
  raw-body access.
- **Wrong secret.** Ensure you're using the correct signing secret
- **Secret in the wrong format.** Some providers expect the secret decoded from
  base64/hex, or with a documented prefix stripped.
- **Replaying old captured payloads with curl.** Verification rejects stale
  timestamps; trigger a fresh delivery (e.g. the provider's "resend") instead.
- **Reverse proxy stripping signature headers.** Check proxy config.
- **Clock skew.** Unsynced server time fails timestamp validation.


## Checklist

- [ ] Signature verified on every request (official library preferred)
- [ ] Verification runs against the **raw** body (no pre-parse)
- [ ] Failed verification returns `400`
- [ ] Handler returns `2xx` within the provider's timeout; heavy work is async
- [ ] Signing secret used, kept server-side
