Typescript/Javascript library for Standard Webhooks 

# Example

Verifying a webhook payload signed with a symmetric secret (`v1`):

```javascript
import { Webhook } from "standardwebhooks"

const wh = new Webhook(base64_secret); // whsec_...
wh.verify(webhook_payload, webhook_headers);
```

Verifying a webhook payload signed with an asymmetric ed25519 key pair (`v1a`), using the public key:

```javascript
import { Webhook } from "standardwebhooks"

const wh = new Webhook(base64_public_key); // whpk_...
wh.verify(webhook_payload, webhook_headers);
```

Signing a webhook with the ed25519 private key:

```javascript
import { Webhook } from "standardwebhooks"

const wh = new Webhook(base64_private_key); // whsk_...
const signature = wh.sign(msgId, timestamp, webhook_payload);
```

# Development

## Requirements

 - node
 - yarn

## Building the library
```sh
yarn
yarn build
```

## Contributing

Before opening a PR be sure to format your code!

```sh
yarn lint:fix
```

## Running Tests

Simply run:

```sh
yarn test
```
