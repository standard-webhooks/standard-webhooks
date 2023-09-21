Typescript/Javascript library for Standard Webhooks 

# Example

Verifying a webhook payload:

```javascript
import { Webhook } from "standardwebhooks"

const wh = new Webhook(base64_secret);
wh.verify(webhook_payload, webhook_headers);
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
