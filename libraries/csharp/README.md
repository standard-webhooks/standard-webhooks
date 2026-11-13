C# library for Standard Webhooks

# Example

Verifying a webhook payload:

```cs
using StandardWebhooks;

var wh = new Webhook(base64Secret);
wh.Verify(webhookPayload, webhookHeaders);
```

Responding to [endpoint verification](../../spec/extensions/endpoint-verification.md):

```cs
var challenge = webhookHeaders.Get("webhook-challenge");
if (challenge != null)
{
    response.Headers["webhook-challenge-response"] = wh.EndpointVerificationResponse(challenge);
    // Not a webhook delivery: respond without processing the body
    response.StatusCode = 204;
    return;
}
```

Verifying a challenge response (for producers):

```cs
// Throws WebhookVerificationException if the response is invalid
wh.VerifyEndpointVerificationResponse(challenge, responseHeader);
```

## Asymmetric signatures

Verifying a webhook payload signed with an asymmetric (`v2a`) signature, using the endpoint's public keys and the endpoint ID assigned by the producer:

```cs
using StandardWebhooks;

var wh = new WebhookAsymmetric("ep_...", new[] { "whpk_..." });
wh.Verify(webhookPayload, webhookHeaders);
```

Keys can be rotated by adding the new key to the start of the list (newest first): a signature made by any of the keys is accepted, and the first key is used for endpoint verification responses. `WebhookAsymmetric` supports the same endpoint verification methods as `Webhook` above.

# Development

## Requirements

 - Dotnet >=10.0

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

