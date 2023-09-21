Python library for Standard Webhooks

# Example

Verifying a webhook payload:

```python
from standardwebhooks.webhooks import Webhook

wh = Webhook(base64_secret)
wh.verify(webhook_payload, webhook_headers)
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
