Ruby library for Standard Webhooks

# Installation

Add `standardwebhooks` to your `Gemfile` and run `bundle install`.

Or install it without bundler:

```sh
gem install standardwebhooks
```

# Verifying webhooks

`StandardWebhooks::Webhook#verify` expects:

- The exact raw request body as a string.
- A hash containing `webhook-id`, `webhook-timestamp`, and `webhook-signature`.

It returns the parsed JSON payload as a Ruby hash and raises
`StandardWebhooks::WebhookVerificationError` when verification fails.

```ruby
require 'standardwebhooks'

webhook = StandardWebhooks::Webhook.new(ENV.fetch('WEBHOOK_SECRET'))

payload = webhook.verify(raw_body, {
	'webhook-id' => request_headers.fetch('webhook-id'),
	'webhook-timestamp' => request_headers.fetch('webhook-timestamp'),
	'webhook-signature' => request_headers.fetch('webhook-signature'),
})

puts payload['type']
```

Pass the raw body exactly as received. Verifying a parsed-and-reserialized JSON body
can fail because the signature is computed over the original bytes.

## Rails example

```ruby
class WebhooksController < ApplicationController
	def create
		webhook = StandardWebhooks::Webhook.new(ENV.fetch('WEBHOOK_SECRET'))

		payload = webhook.verify(request.raw_post, {
			'webhook-id' => request.headers.fetch('webhook-id'),
			'webhook-timestamp' => request.headers.fetch('webhook-timestamp'),
			'webhook-signature' => request.headers.fetch('webhook-signature'),
		})

		process_event(payload)

		head :ok
	rescue StandardWebhooks::WebhookVerificationError => error
		Rails.logger.warn("Invalid webhook: #{error.message}")

		head :bad_request
	end

	private

	def process_event(payload)
		case payload['type']
		when 'customer.created'
			CustomerCreateJob.perform_later(payload.fetch('data'))
		end
	end
end
```

## Rack or Sinatra example

```ruby
post '/webhooks' do
	request.body.rewind
	raw_body = request.body.read

	webhook = StandardWebhooks::Webhook.new(ENV.fetch('WEBHOOK_SECRET'))

	payload = webhook.verify(raw_body, {
		'webhook-id' => request.env.fetch('HTTP_WEBHOOK_ID'),
		'webhook-timestamp' => request.env.fetch('HTTP_WEBHOOK_TIMESTAMP'),
		'webhook-signature' => request.env.fetch('HTTP_WEBHOOK_SIGNATURE'),
	})

	handle_event(payload)

	status 204
rescue StandardWebhooks::WebhookVerificationError
	halt 400
end
```

# Signing payloads

If you are producing Standard Webhooks or need deterministic signatures in tests,
use `#sign`:

```ruby
require 'standardwebhooks'

webhook = StandardWebhooks::Webhook.new(ENV.fetch('WEBHOOK_SECRET'))

msg_id = 'msg_2KWPBgLlAfxdpx2AI54pPJ85f4W'
timestamp = Time.now.to_i
payload = '{"type":"example.event","timestamp":"2022-11-03T20:26:10.344522Z","data":{"foo":"bar"}}'

signature = webhook.sign(msg_id, timestamp, payload)

headers = {
	"webhook-id" => msg_id,
	"webhook-timestamp" => timestamp.to_s,
	"webhook-signature" => signature,
}

# …
```

# Development

## Building

```sh
bundler exec rake build
```

## Running tests

```sh
bundle exec rspec spec
```
