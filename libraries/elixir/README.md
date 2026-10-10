Elixir library for Standard Webhooks

# Example

Verifying a webhook payload:

```elixir
StandardWebhooks.verify(webhook_payload, plug_conn, webhook_secret)
```

Note: [Plug](https://hexdocs.pm/plug/Plug.Conn.html#t:headers/0) contains the request headers.

Signing a webhook

```elixir
StandardWebhooks.sign(webhook_id, webhook_timestamp, webhook_payload, webhook_secret)
```

Responding to a challenge-response check (CRC):

```elixir
conn =
  case Plug.Conn.get_req_header(conn, "webhook-challenge") do
    [challenge] ->
      response = StandardWebhooks.challenge_response(challenge, webhook_secret)
      Plug.Conn.put_resp_header(conn, "webhook-challenge-response", response)

    _ ->
      conn
  end
```

Producers can verify the `webhook-challenge-response` header with `StandardWebhooks.verify_challenge_response(challenge, header, webhook_secret)`.

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