<h1>
    <a style="text-decoration: none" href="https://www.standardwebhooks.com">
      <img width="360" src="./assets/brand.svg" />
    </a>
</h1>

Open source tools and guidelines for sending webhooks easily, securely and reliably

## Introduction

Webhooks are becoming increasingly popular, and are used by many of the world's top companies to notify users of their APIs of events. Implementations, however, are heavily fragmented, and every webhooks provider implements things differently and with varying quality. In addition, even the higher quality implementations are different to one another which means they are inherently incompatible. This fragmentation is a pain for the whole ecosystem, both providers and consumers, is wasteful, and is holding back innovation.

For consumers this means having to implement webhook handling differently for every provider, having to relearn how to verify webhooks, and encounter many gotchas with weird implementations. For providers this means reinventing the wheel every time, and making costly mistakes around issues that have already been solved elsewhere (security, forward compatibility, etc.). It also holds the ecosystem back as a whole, as these incompatibilities mean that no tools are being built to help senders send, consumers consume, and for everyone to innovate on top.

The solution is simple: have a standard way of implementing webhooks. This design document aims to outline exactly that, a set of strict webhook guidelines based on the existing industry best practices; we call it "Standard Webhooks".

We believe "Standard Webhooks" can do to webhooks what JWT did to API authentication. Having a common protocol that is consistent and supported by different implementations will solve the above issues, and will usher in an era of new tools and innovations in the world of webhooks.

To achieve this, we have created a fully open source and community driven set of tools and guidelines for sending webhooks. Part of which is the document you are currently reading.

## What are webhooks?

Webhooks are a common name for HTTP callbacks, and are how services notify each other of events. Webhooks are part of a service's API, though you can think of them as a sort of a reverse API. When a client wants to make a request to a service they make an API call, and when the service wants to notify the client of an event the service triggers a webhook ("a user has paid", "task has finished", etc.).

Webhooks are server-to-server, in the sense that both the customer and the service in the above description, should be operating HTTP servers, one to receive the API calls and one to receive the webhooks.It's important to note that while webhooks usually co-exist with a traditional API, this is not a requirement, and some services send webhooks without offering a traditional API.

## Read the specification

The latest draft specification can be found at [spec/standard-webhooks.md](./spec/standard-webhooks.md) which tracks the latest commit to the master branch in this repository.
The human-readable markdown file is the source of truth for the specification.

## Reference implementations

**IMPORTANT:** The reference implementations will move to their own repository upon release of this spec.

There are reference implementations for the signature verification theme for a variety of languages, including:

- [C#](https://github.com/svix/svix-webhooks/tree/main/csharp)
- [Go](https://github.com/svix/svix-webhooks/tree/main/go)
- [Java](https://github.com/svix/svix-webhooks/tree/main/java)
- [JavaScript/TypeScript](https://github.com/svix/svix-webhooks/tree/main/javascript)
- [Kotlin](https://github.com/svix/svix-webhooks/tree/main/kotlin)
- [PHP](https://github.com/svix/svix-webhooks/tree/main/php)
- [Python](https://github.com/svix/svix-webhooks/tree/main/python)
- [Ruby](https://github.com/svix/svix-webhooks/tree/main/ruby)
- [Rust](https://github.com/svix/svix-webhooks/tree/main/rust)


## Technical steering committee

The Standard Webhooks initiative, the specification, and development of tooling is driven by the community and guided by the technical steering committee.

Members (in alphabetical order):

* [Brian Cooksey](https://github.com/bcooksey) ([Zapier](https://zapier.com/))
* [Ivan Gracia](https://github.com/igracia) ([Twilio](https://twilio.com/))
* [Matthew McClure](https://github.com/mmcc) ([Mux](https://mux.com))
* [Tom Hacohen](https://github.com/tasn/) ([Svix](https://www.svix.com))


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
