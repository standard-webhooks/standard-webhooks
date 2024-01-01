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

The package can be installed by adding `standard_webhooks` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    # ... your other deps
    {:standard_webhooks, "~> 0.1.0"}
  ]
end
```

Then run:

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

## Code Quality

```sh
mix quality
```