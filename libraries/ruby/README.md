Ruby library for Standard Webhooks 

# Example

Verifying a webhook payload:

```ruby
require "standardwebhooks"

wh = StandardWebhooks::Webhook.new(base64_secret)
wh.verify(webhook_payload, webhook_headers)
```

# Development

## Building

```sh
bundler exec rake build
```

## Contributing

Before opening a PR be sure to format your code!

```sh
bundle exec rspec spec
```

## Running Tests

Simply run:

```sh
bundle exec rspec spec
```
