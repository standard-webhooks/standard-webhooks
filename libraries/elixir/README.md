Elixir library for Standard Webhooks

# Example

Verifying a webhook payload:

```elixir
StandardWebhooks.verify(plug_conn, webhook_payload, webhook_secret)
```

Signing a webhook

```elixir
StandardWebhooks.sign(webhook_id, webhook_timestamp, webhook_payload, webhook_secret)
```

# Development

## Installation

```sh
mix deps.get
```

## Elixir Console

```sh
iex -S mix
```

## Running Tests

Simply run:

```sh
mix test
```
