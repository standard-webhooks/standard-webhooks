Rust library for Standard Webhooks 

# Example

Verifying a webhook payload:

```rust
use standardwebhooks::Webhook;

let wh = Webhook::new(base64_secret);
wh.verify(webhook_payload, webhook_headers).expect("Webhook verification failed");
```

Responding to a challenge-response check (CRC):

```rust
use standardwebhooks::{HEADER_WEBHOOK_CHALLENGE, HEADER_WEBHOOK_CHALLENGE_RESPONSE};

if let Some(challenge) = request_headers.get(HEADER_WEBHOOK_CHALLENGE) {
    let challenge = challenge.to_str().expect("Invalid challenge header");
    response_headers.insert(
        HEADER_WEBHOOK_CHALLENGE_RESPONSE,
        wh.challenge_response(challenge).parse().unwrap(),
    );
}
```

Producers can verify the `webhook-challenge-response` header with `wh.verify_challenge_response(challenge, header)`.
