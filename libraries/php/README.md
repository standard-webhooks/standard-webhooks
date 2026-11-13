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
    // Not a webhook delivery: respond without processing the body
    http_response_code(204);
    exit;
}
```

Verifying a challenge response (for producers):

```php
// Throws WebhookVerificationException if the response is invalid
$wh->verifyEndpointVerificationResponse($challenge, $responseHeaders['webhook-challenge-response']);
```

## Asymmetric signatures

Webhooks signed with asymmetric (`v2a`) signatures are verified with `WebhookAsymmetric`, which takes the endpoint ID and the list of trusted public keys (`whpk_...`) the producer shared with you.
A webhook is accepted if it's signed by any of the keys, so keys can be rotated by adding the new key to the list.
Put the newest key first, as endpoint verification responses are calculated with the first key.

```php
$wh = new \StandardWebhooks\WebhookAsymmetric($endpointId, [$publicKey]);
$wh->verify($webhookPayload, $webhookHeaders);
```

`WebhookAsymmetric` also supports `endpointVerificationResponse` and `verifyEndpointVerificationResponse`.

### Required Dependencies

Standard Webhooks PHP requires the following extensions in order to run:

- [`json`](https://secure.php.net/manual/en/book.json.php)
- [`sodium`](https://secure.php.net/manual/en/book.sodium.php) (for `WebhookAsymmetric`)

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
