Typescript/Javascript library for Standard Webhooks 

# Example

Verifying a webhook payload:

```javascript
import { Webhook } from "standardwebhooks"

const wh = new Webhook(base64_secret);
wh.verify(webhook_payload, webhook_headers);
```

Responding to a [challenge-response check](../../spec/extensions/crc.md):

```javascript
const challenge = webhook_headers["webhook-challenge"];
if (challenge) {
  response_headers["webhook-challenge-response"] = wh.challengeResponse(challenge);
}
```

Verifying the response as a producer (throws `WebhookVerificationError` if it doesn't match):

```javascript
wh.verifyChallengeResponse(challenge, response_headers["webhook-challenge-response"]);
```

# Development

## Requirements

 - node
 - npm

## Building the library
```sh
npm install
npm run build
```

## Contributing

Before opening a PR be sure to format your code!

```sh
npm run check:fix
```

## Running Tests

Simply run:

```sh
npm test
```
