C# library for Standard Webhooks

# Example

Verifying a webhook payload:

```cs
using StandardWebhooks;

var wh = new Webhook(base64Secret);
wh.Verify(webhookPayload, webhookHeaders);
```

Responding to a [challenge-response check (CRC)](../../spec/extensions/crc.md):

```cs
var challenge = webhookHeaders.Get("webhook-challenge");
if (challenge != null)
{
    response.Headers["webhook-challenge-response"] = wh.ChallengeResponse(challenge);
}
```

Verifying a challenge response (for producers):

```cs
// Throws WebhookVerificationException if the response is invalid
wh.VerifyChallengeResponse(challenge, responseHeader);
```

# Development

## Requirements

 - Dotnet >=5.0

## Building the library
```sh
dotnet build
```

## Contributing

Before opening a PR be sure to format your code!

We use [dotnet-format](https://github.com/dotnet/format) for this project.

First install it then run:
```sh
dotnet-format
```

## Running Tests

Simply run:

```sh
dotnet test StandardWebhooks.Tests
```

