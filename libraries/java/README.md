Java library for Standard Webhooks

# Example

Verifying a webhook payload:

```java
import com.standardwebhooks.Webhook;

Webhook webhook = new Webhook(base64Secret);
webhook.verify(webhookPayload, webhookHeaders);
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

