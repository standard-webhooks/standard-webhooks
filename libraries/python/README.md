Python library for Standard Webhooks

# Example

Verifying a webhook payload:

```python
from standardwebhooks.webhooks import Webhook

wh = Webhook(base64_secret)
wh.verify(webhook_payload, webhook_headers)
```

`webhook_payload` must be the raw request body exactly as received, before any JSON parsing.
Pass it as `bytes` to verify the bytes as sent, including bodies that aren't valid UTF-8. A
`str` is verified as its UTF-8 encoding.

Responding to [endpoint verification](../../spec/extensions/endpoint-verification.md):

```python
challenge = webhook_headers.get("webhook-challenge")
if challenge:
    response_headers["webhook-challenge-response"] = wh.endpoint_verification_response(challenge)
    # Not a webhook delivery: respond (e.g. with 204 No Content) without processing the body
    return
```

Verifying the response as a producer (raises `WebhookVerificationError` if it doesn't match):

```python
wh.verify_endpoint_verification_response(challenge, response_headers["webhook-challenge-response"])
```

# Development

## Requirements

 - python 3

## Installing dependencies

```sh
python -m venv .venv
pip install -r requirements.txt && pip install -r requirements-dev.txt
```

## Contributing

Before opening a PR be sure to format your code!

```sh
./scripts/format.sh
```

## Running Tests

Simply run:

```sh
pytest
```
