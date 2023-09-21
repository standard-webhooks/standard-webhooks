Rust library for Standard Webhooks 

# Example

Verifying a webhook payload:

```rust
use standardwebhooks::Webhook;

let wh = Webhook::new(base64_secret);
wh.verify(webhook_payload, webhook_headers).expect("Webhook verification failed");
```