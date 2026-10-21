PHP library for Standard Webhooks 

# Installation

# Example

Verifying a webhook payload:

```php
$wh = new \StandardWebhooks\Webhook($base64Secret);
$wh->verify($webhookPayload, $webhookHeaders);
```

Responding to [endpoint verification](../../spec/extensions/endpoint-verification.md):

```php
if (isset($webhookHeaders['webhook-challenge'])) {
    header('webhook-challenge-response: ' . $wh->endpointVerificationResponse($webhookHeaders['webhook-challenge']));
}
```

Verifying a challenge response (for producers):

```php
// Throws WebhookVerificationException if the response is invalid
$wh->verifyEndpointVerificationResponse($challenge, $responseHeaders['webhook-challenge-response']);
```

### Required Dependencies

Standard Webhooks PHP requires the following extensions in order to run:

- [`json`](https://secure.php.net/manual/en/book.json.php)

If you use Composer, these dependencies should be handled automatically. If you install manually, you'll want to make sure that these extensions are available.

# Development

## Requirements

 - PHP >= 5.6.0

## Installing dependencies
```sh
composer install
```

## Contributing

Before opening a PR be sure to format your code!

```sh
composer install
./vendor/bin/php-cs-fixer fix -v --using-cache=no .
```

## Running Tests

Simply run:

```sh
composer install
./vendor/bin/phpunit php/tests
```
