<h1>
    <a style="text-decoration: none" href="https://www.standardwebhooks.com">
      <img width="360" src="./assets/brand.svg" />
    </a>
</h1>

Open source tools and guidelines for sending webhooks easily, securely, and reliably

## Introduction

Webhooks are becoming increasingly popular and are used by many of the world's top companies for sending events to users of their APIs. However, the ecosystem is fragmented, with each webhook provider using different implementations and varying quality. Even high quality implementations vary, making them inherently incompatible. This fragmentation is a pain for the providers and consumers, stifling innovation.

For consumers, this means handling webhooks differently for every provider, relearning how to verify webhooks, and encountering gotchas with bespoke implementations. For providers, this means reinventing the wheel, redesigning for issues that have already been solved (security, forward compatibility, etc.). 

We propose a simple solution: standardize webhooks across the industry. This design document outlines our proposal, a set of strict webhook guidelines based on the existing industry best practices. We call it "Standard Webhooks".

We believe "Standard Webhooks" can do for webhooks what JWT did for API authentication. Adopting a common protocol that is consistent and supported by different implementations will solve the above issues, and will enable new tools and innovations in webhook ecosystem.

To achieve this, we have created an open source and community-driven set of tools and guidelines for sending webhooks. 

## What are Webhooks?

Webhooks are a common name for HTTP callbacks, and are a way for services to notify each other of events. Webhooks are part of a service's API, though you can think of them as a sort of a "reverse API". When a client wants to make a request to a service they make an API call, and when the service wants to notify the client of an event the service triggers a webhook ("a user has paid", "task has finished", etc.).

Webhooks are server-to-server, in the sense that both the customer and the service in the above description, should be operating HTTP servers, one to receive the API calls and one to receive the webhooks.It's important to note that while webhooks usually co-exist with a traditional API, this is not a requirement, and some services send webhooks without offering a traditional API.

## Read the specification

The latest draft specification can be found at [spec/standard-webhooks.md](./spec/standard-webhooks.md) which tracks the latest commit to the master branch in this repository.
The human-readable markdown file is the source of truth for the specification.

## Reference implementations

There are reference implementations for the signature verification theme for a variety of languages, including:

- [Python](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/python)
- [JavaScript/TypeScript](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/javascript)
- [Java/Kotlin](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/java)
- [Rust](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/rust)
- [Go](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/go)
- [Ruby](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/ruby)
- [PHP](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/php)
- [C#](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/csharp)


## Technical steering committee

The Standard Webhooks initiative, the specification, and development of tooling is driven by the community and guided by the technical steering committee.

Members (in alphabetical order):

* [Brian Cooksey](https://github.com/bcooksey) ([Zapier](https://zapier.com/))
* [Ivan Gracia](https://github.com/igracia) ([Twilio](https://twilio.com/))
* [Jorge Vivas](https://github.com/jorgelob) ([Lob](https://lob.com))
* [Matthew McClure](https://github.com/mmcc) ([Mux](https://mux.com))
* [Nijiko Yonskai](https://github.com/nijikokun) ([ngrok](https://ngrok.com))
* [Stojan Dimitrovski](https://github.com/hf) ([Supabase](https://supabase.com))
* [Tom Hacohen](https://github.com/tasn/) ([Svix](https://www.svix.com))
* [Vincent Le Goff](https://github.com/zekth) ([Kong](https://konghq.com))

## Example ecosystem benefits of Standard Webhooks

We believe "Standard Webhooks" can do to webhooks what JWT did to API authentication. Having a common protocol that is consistent will enable a variety of implementations to interoperate, reducing the development burden on webhook consumers and enabling new uses. Some of these benefits include:

- API Gateway signature verification: signature verification is a common challenge for webhook consumers. Standard Webhooks makes it possible for verification to be implemented directly in the API gateway, easily solving verification for consumers.
- Having a set of libraries for signing and verification make webhook verification easier for scenarios where API gateways can't be used.
- Workflow automation tools (such as Zapier, Make, Workato, and tray.io) can implement the signature verification themselves to ensure a secure integration and save the need for integration builders to reinvent the wheel every time.
- Standard Webhooks will enable building tools to automatically generate SDK for webhook consumers that in addition to verifying the signature can also validate the schemas (using JSON Schema, OpenAPI or AsyncAPI definitions).
- Many more...


## Related efforts

There are a few complementary or partially overlapping efforts to standardize asynchronous event communication. This specification is compatible with the rest of them, and can either reuse existing efforts or benefit further from collaboration with them. The most notable of such efforts are:

- [OpenAPI](https://www.openapis.org/)
- [AsyncAPI](https://www.asyncapi.com/)
- [CloudEvents](https://cloudevents.io/)
- [IETF HTTP Message Signatures](https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html)
- [REST Hooks](http://resthooks.org/)
- [Webhooks.fyi](https://webhooks.fyi/) - a collection of useful webhooks resources (not a standardization effort).
