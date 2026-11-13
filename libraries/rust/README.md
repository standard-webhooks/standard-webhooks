Rust library for Standard Webhooks 

# Example

Verifying a webhook payload:

```rust
use standardwebhooks::Webhook;

let wh = Webhook::new(base64_secret);
wh.verify(webhook_payload, webhook_headers).expect("Webhook verification failed");
```

## Asymmetric signatures

Verifying a webhook payload signed with asymmetric (`v2a`) signatures, using the public keys and the endpoint ID shared by the producer:

```rust
use standardwebhooks::WebhookAsymmetric;

let wh = WebhookAsymmetric::new("ep_...", &["whpk_..."]).expect("Invalid public key or endpoint ID");
wh.verify(webhook_payload, webhook_headers).expect("Webhook verification failed");
```

A webhook is accepted if it was signed by any of the public keys in the list, so keys can be rotated by adding the new key to the list. Put the newest key first: it's the one used for responding to endpoint verification.

## Endpoint verification

Responding to [endpoint verification](../../spec/extensions/endpoint-verification.md):

```rust
use standardwebhooks::{HEADER_WEBHOOK_CHALLENGE, HEADER_WEBHOOK_CHALLENGE_RESPONSE};

if let Some(challenge) = request_headers.get(HEADER_WEBHOOK_CHALLENGE) {
    let challenge = challenge.to_str().expect("Invalid challenge header");
    response_headers.insert(
        HEADER_WEBHOOK_CHALLENGE_RESPONSE,
        wh.endpoint_verification_response(challenge).parse().unwrap(),
    );
    // Not a webhook delivery: respond (e.g. with 204 No Content) without processing the body
    return;
}
```

Producers can verify the `webhook-challenge-response` header with `wh.verify_endpoint_verification_response(challenge, header)`.

Both work the same way with `WebhookAsymmetric`.
