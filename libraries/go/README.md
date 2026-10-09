Go library for Standard Webhooks

# Example

Verifying a webhook payload:

```go
import (
    standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

wh, err := standardwebhooks.NewWebhook(base64Secret)
err = wh.Verify(webhookPayload, webhookHeaders)
```

Responding to a challenge-response check (CRC):

```go
if challenge := r.Header.Get(standardwebhooks.HeaderWebhookChallenge); challenge != "" {
    w.Header().Set(standardwebhooks.HeaderWebhookChallengeResponse, wh.ChallengeResponse(challenge))
}
```

Producers can verify the `webhook-challenge-response` header with `wh.VerifyChallengeResponse(challenge, header)`.

# Development

## Requirements

 - go >= 1.16

## Contributing

Before opening a PR be sure to format your code!

```sh
go fmt ./...
```

## Running Tests

Simply run:

```sh
go test ./...
```

## Publishing

Releases use go modules and are automatically published by tagging the release commit.
