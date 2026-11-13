Java library for Standard Webhooks

# Example

Verifying a webhook payload:

```java
import com.standardwebhooks.Webhook;

Webhook webhook = new Webhook(base64Secret);
webhook.verify(webhookPayload, webhookHeaders);
```

Responding to [endpoint verification](../../spec/extensions/endpoint-verification.md):

```java
String challenge = request.getHeader("webhook-challenge");
if (challenge != null) {
    response.setHeader("webhook-challenge-response", webhook.endpointVerificationResponse(challenge));
    // Not a webhook delivery: respond without processing the body
    response.setStatus(204);
    return;
}
```

Verifying a challenge response (for producers):

```java
// Throws WebhookVerificationException if the response is invalid
webhook.verifyEndpointVerificationResponse(challenge, responseHeader);
```

## Asymmetric signatures

Verifying a webhook payload signed with an asymmetric (`v2a`) signature, using the endpoint's public keys and the endpoint ID assigned by the producer:

```java
import com.standardwebhooks.WebhookAsymmetric;

WebhookAsymmetric webhook = new WebhookAsymmetric("ep_...", Arrays.asList("whpk_..."));
webhook.verify(webhookPayload, webhookHeaders);
```

Keys can be rotated by adding the new key to the start of the list (newest first): a signature made by any of the keys is accepted, and the first key is used for endpoint verification responses. `WebhookAsymmetric` supports the same endpoint verification methods as `Webhook` above.

# Development

## Requirements

 - Java 1.8+
 - Gradle

## Building the library
```sh
./gradlew build
```

## Running Tests

Simply run:

```sh
./gradlew test
```

## Publishing to Maven

```sh
./gradlew publishToSonatype closeAndReleaseSonatypeStagingRepository
```

