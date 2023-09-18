C# library for Standard Webhooks

# Example

Verifying a webhook payload:

```cs
using StandardWebhooks;

var wh = new Webhook(base64Secret);
wh.Verify(webhookPayload, webhookHeaders);
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

