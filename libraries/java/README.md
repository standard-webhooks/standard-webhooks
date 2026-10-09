Java library for Standard Webhooks

# Example

Verifying a webhook payload:

```java
import com.standardwebhooks.Webhook;

Webhook webhook = new Webhook(base64Secret);
webhook.verify(webhookPayload, webhookHeaders);
```

Responding to a [challenge-response check (CRC)](../../spec/extensions/crc.md):

```java
String challenge = request.getHeader("webhook-challenge");
if (challenge != null) {
    response.setHeader("webhook-challenge-response", webhook.challengeResponse(challenge));
}
```

Verifying a challenge response (for producers):

```java
// Throws WebhookVerificationException if the response is invalid
webhook.verifyChallengeResponse(challenge, responseHeader);
```

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

