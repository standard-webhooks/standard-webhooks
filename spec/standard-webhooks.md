<h1>
    <a style="text-decoration: none" href="https://www.standardwebhooks.com">
      <img width="360" src="../assets/brand.svg" />
    </a>
</h1>

## Open source tools and guidelines for sending webhooks easily, securely and reliably

Version: 1.0.0

License: The Apache License, Version 2.0.

## Introduction

Webhooks are becoming increasingly popular, and are used by many of the world's top companies to notify users of their APIs of events. Implementations, however, are heavily fragmented, and every webhooks provider implements things differently and with varying quality. In addition, even the higher quality implementations are different to one another which means they are inherently incompatible. This fragmentation is a pain for the whole ecosystem, both providers and consumers, is wasteful, and is holding back innovation.

For consumers this means having to implement webhook handling differently for every provider, having to relearn how to verify webhooks, and encounter many gotchas with weird implementations. For providers this means reinventing the wheel every time, and making costly mistakes around issues that have already been solved elsewhere (security, forward compatibility, etc.). It also holds the ecosystem back as a whole, as these incompatibilities mean that no tools are being built to help senders send, consumers consume, and for everyone to innovate on top.

The solution is simple: have a standard way of implementing webhooks. This design document aims to outline exactly that, a set of strict webhook guidelines based on the existing industry best practices; we call it "Standard Webhooks".

We believe "Standard Webhooks" can do to webhooks what JWT did to API authentication. Having a common protocol that is consistent and supported by different implementations will solve the above issues, and will usher in an era of new tools and innovations in the world of webhooks.

To achieve this, we have created a fully open source and community driven set of tools and guidelines for sending webhooks. Part of which is the document you are currently reading.

## What are webhooks?

Webhooks are a common name for HTTP callbacks, and are how services notify each other of events. Webhooks are part of a service's API, though you can think of them as a sort of a reverse API. When a client wants to make a request to a service they make an API call, and when the service wants to notify the client of an event the service triggers a webhook ("a user has paid", "task has finished", etc.).

Webhooks are server-to-server, in the sense that both the customer and the service in the above description, should be operating HTTP servers, one to receive the API calls and one to receive the webhooks.It's important to note that while webhooks usually co-exist with a traditional API, this is not a requirement, and some services send webhooks without offering a traditional API.

## Design Goals

These are the principles and goals guiding the design and development of this specification.

- **Secure.** Make it easy for implementations to be secure, and hard to be insecure.
- **Reliable.** In order for webhooks to be relied upon, they have to be reliable.
- **Interoperable.** It has to enable interoperability and compatibility across different providers, consumers, and utilities.
- **Simple.** Simplicity is key, it must not add undue complexity to existing systems.
- **Backward and forward compatible.** It has to support working in tandem both with existing webhook implementations and future ones.

## Specification

The Standard Webhooks specification is a set of conventions to be followed by webhook producers (senders) to provide webhook consumers (receivers) a secure, consistent, and interoperable interface for webhooks. The specification includes both requirements for any compatible implementation and recommendations that are not necessarily required for compatibility, but provide a better experience for the producers, consumers, or both.

### Payload

The payload is the core part of every webhook. It is the actual data being sent as part of the webhook, and usually consists of important information about the event and related information.

While this specification does not dictate the structure, or impose any requirements, on the shape, format, and content of the payload it does offer recommendations.

#### Payload structure

- The payload should be passed in the HTTP body.
- The payload should be [JSON formatted](https://en.wikipedia.org/wiki/JSON) for maximum compatibility, but other content types can be used as well.
- It's recommended to provide examples of the payload structure for each of the event types, as well as a formal specification of the structure (such as JSON Schema or OpenAPI).
- Payload structure:
  - `type`: a full-stop delimited type associated with the event. The type indicates the type of the event being sent (e.g "user.created" or "invoice.paid"), indicates the schema of the payload (passed in data), and it should be grouped hierarchically.
  - `timestamp`: the timestamp of when the event occurred (not necessarily the same of when it was delivered).
  - `data`: the actual event data associated with the event. It can either be passed as part of the data property, or squashed as part of the top-level object.
  - Additional metadata can be added both as top-level properties or as part of data, depending on personal preference.

Example payload:

```json
{
  "type": "example.event",
  "timestamp": "2022-11-03T20:26:10.344522Z",
  "data": {
    "foo": "bar",
    "fizzbuzz": 2
  }
}
```

#### "Thin" vs "full" payloads

There are two main approaches to webhook payloads: "thin" and "full" payloads. Full payloads consist of the full information about the event, the status of the related entities, and everything that's changed. A thin payload will only include identifiers to the affected entities, and potentially information about the change itself.

Let's consider a fictional address book management service. It's a simple service where you can update and maintain your address book, and it sends webhooks every time data changes. 

Now, let's assume we just created a new contact, here are the payloads that will be sent:

Full payload:

```json
{
  "type": "contact.created",
  "timestamp": "2022-11-03T20:26:10.344522Z",
  "data": {
    "id": "1f81eb52-5198-4599-803e-771906343485",
    "type": "contact",
    "fullName": "John Smith",
    "address": "800 W NASA Pkwy, Webster, TX 77598, USA",
    "phoneNumber": "(281) 332-2575",
    "birthday": "1980-04-19",
    "occupation": "Engineer, ACME"
  }
}
```

Thin payload:

```json
{
  "type": "contact.created",
  "timestamp": "2022-11-03T20:26:10.344522Z",
  "data": {
    "id": "1f81eb52-5198-4599-803e-771906343485"
  }
}
```

Thin and full payloads are not a binary decision, for example, one can decide to take the thin payload approach, but also include the "fullName" field as that one is commonly used and is very useful.

There are pros and cons for both, and which to go for depends on the specific requirements. The main advantage of using full payloads is that most of the information is available for the webhook consumer without needing to make additional API calls to get more data. Thin payloads, however, offer better performance (sending and generating less data, often), more flexibility (it's not always trivial to query the database for the full payload data for the webhook from every context in the code), and it's more future proof (you can always make a thin one full, but not the other way around). Another important advantage of thin payloads is that they provide for better control over the flow of data. In many scenarios, it's preferable (if not required) to have an audit log for when certain data is accessed. With full payloads, the data is just sent to every listening endpoint, with thin payloads it's required that people explicitly query the data they need, making it possible to make access auditable and more restricted.

#### Payload size

While there are no technical limitations to the size of webhook payloads, it's recommended to keep the size of payloads small, usually smaller than 20kb. There are multiple reasons for this, but the main one is that as a webhook producer you are imposing unnecessary load on the webhook consumer. They may not be interested in this specific event, and they are surely not interested in all of the data being sent. By keeping the payload size small, you put the control in the hands of the consumers.

If you find yourself needing to send large amounts of data (e.g. images or other assets), consider uploading them somewhere and passing the link in the webhook, or if the data is dynamic, just include the resource or URL they need to query.

### Verifying webhook authenticity

Webhooks are just HTTP requests from an unknown source, so verifying the authenticity of webhooks is a requirement for any secure webhook implementation.

There are multiple ways to verify the authenticity of webhooks, with some being much better than others. The most common way to verify the authenticity of webhooks is by using HMAC signatures using a pre-shared secret key, with a common alternative being the use of asymmetric signatures (more on that below).

As often the case with security, using the correct cryptographic primitives for the signature verification is not sufficient for a secure implementation. This section provides a secure scheme and additional guidelines for ensuring a simple and secure implementation.

#### Webhook metadata

In addition to the payload itself, webhook implementations often include two important pieces of metadata: the timestamp of the attempt, and a unique identifier associated with the webhook. A secure signature scheme should verify the authenticity of both the payload, and the additional metadata (timestamp and unique identifier).

The timestamp of the attempt is the timestamp of when the webhook attempt has been made. The timestamp of the attempt may be different to the timestamp of the event that generated the attempt. One common example of where this happens: failed deliveries. Every time an attempt is retried the timestamp of the attempt is updated, while the timestamp of the original event remains the same. The attempt's timestamp as an important security measure meant to prevent replay attacks.

The unique identifier is a unique identifier associated with a specific event triggered, and it remains the same no matter how many times a webhook that has failed is retried. The ID is often used as an idempotency key, which lets a consumer ensure that they only process a specific event once, even if sent multiple times maliciously, in error, or due to networking issues.

#### Signature scheme

As mentioned above, it's important to sign both the body of the webhook, and the associated metadata. To achieve this, the metadata and the body are concatenated (delimited by full-stops) and then signed.

The content to be signed is therefore: `{msg_id}.{timestamp}.{payload}`.

For example:

```
msg_2KWPBgLlAfxdpx2AI54pPJ85f4W.1674087231.{
  "type": "contact.created",
  "timestamp": "2022-11-03T20:26:10.344522Z",
  "data": {
    "id": "1f81eb52-5198-4599-803e-771906343485"
  }
}
```

Or more likely, with a minified JSON (assuming that's what is sent):

```
msg_2KWPBgLlAfxdpx2AI54pPJ85f4W.1674087231.{"type":"contact.created","timestamp":"2022-11-03T20:26:10.344522Z","data":{"id":"1f81eb52-5198-4599-803e-771906343485"}}
```

It's important that both the message id and the timestamp not be user controlled, or at the very least not be allowed to include any `.` to prevent certain attacks.

Note: while it's OK (and recommended) to minimize the JSON body when serialized for sending, it's important to make sure that the payload sent is the same as the payload signed. Cryptographic signatures are sensitive to even the smallest changes, and even a stray space can cause the signature to be invalid. This is a very common failure mode as many webhook consumers often accidentally parse the body as json, and then serialize it again, which can cause for failed verification due to minor changes in serialization of JSON (which is not necessarily the same across implementations, or even multiple invocations of the same implementation).

This specification allows for both symmetric and asymmetric signatures, and depending on which is used, may require slightly different handling. There are no limitations on their usage, and for example one consumer may use symmetric, and another may use asymmetric, or even the same consumer may change back and forth between them.

There are a few differences between symmetric and asymmetric signatures and how they are used:

|                      | Symmetric                                                         | Asymmetric                                                                                                            |
| -------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Signature scheme     | `HMAC-SHA256`                                                     | `ed25519`                                                                                                             |
| Signing secret       | Random. At least 24 bytes (192 bits)                              | Standard ed25519 key pair                                                                                             |
| Secret serialization | base64 encoded, prefixed with \`whsec_\` for easy identification. | base64 encoded, prefixed with \`whsk_\` for the secret key, and \`whpk_\` for the public key for easy identification. |
| Signature identifier | `v1`                                                              | `v1a`                                                                                                                 |


Comparison:

- Symmetric:
  - Fast. HMAC-SHA256 is blazing fast on modern hardware, and much faster than any asymmetric scheme by orders of magnitude both for the producers and the consumers.
  - Simple. Symmetric signatures are much more simple than asymmetric ones.
  - Ubiquitous: HMAC-SHA256 is widely available on every platform and language

- Asymmetric:
  - Provides an additional layer of security, because the \`whpk_\`, the one that’s shared with consumers, doesn’t need to be secret.

The "secret serialization" row refers to how secrets should be serialized when presented to customers. Having a unique and consistent secret format allows implementations to correctly use the correct scheme without additional configuration, and to ensure keys are used as expected.

The "signature identifier" is the version identifier prefixed to signatures when serialized and passed to customers (more on that in the "webhook headers" section). Symmetric signatures are prefixed with `v1` and asymmetric with `v1a`. So for example, a symmetric signature will be v1, followed by a comma (`,`), followed by the base64 encoded signature. For example: `v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=`.

##### Additional considerations:

- Signing keys should be unique per endpoint for symmetric signatures, and unique per endpoint (or potentially customer) for asymmetric signatures. Reusing keys across customers can lead to security issues!
- It's almost always recommended to choose symmetric signatures when possible, as the performance implications of asymmetric signatures are quite severe.

#### Webhook headers (sending metadata to consumers)

As discussed above, the webhook payload should be sent as the body of an HTTP POST request, which means that additional webhook data should be sent as part of the headers.

All of the headers should be prefixed with `webhook-` and follow the exact naming as below.

The headers are:

- `webhook-id`: the unique webhook identifier described in the sections above.
- `webhook-timestamp`: integer unix timestamp (seconds since epoch).
- `webhook-signature`: the signature(s) of this webhook.

The signature header is a space delimited list of signatures associated with this webhook. The reason it is a list, and not just one signature is to support zero downtime secret rotation. The secret key used for the signature should not be changed under normal circumstances, but it may be required that it does change under some circumstances (e.g. compromise). Supporting zero downtime secret rotation means that webhook operations won't be affected during the secret rotation process.

To achieve this, the webhook is signed both using the current key, and using an old key (for a set period of time), and both signatures are sent, space delimited, in the `webhook-signature` header. Webhook consumers can try to verify each signature until one matches. Signing with multiple keys, even compromised ones, doesn't diminish the security of the scheme, as the consumer still requires a valid signature.

Example headers:

```
webhook-id: msg_2KWPBgLlAfxdpx2AI54pPJ85f4W\
webhook-timestamp: 1674087231
webhook-signature: v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4= v1a,hnO3f9T8Ytu9HwrXslvumlUpqtNVqkhqw/enGzPCXe5BdqzCInXqYXFymVJaA7AZdpXwVLPo3mNl8EM+m7TBAg==
```

#### Verifying signatures

Verifying signatures is similar to creating them, though there are a few considerations:

- When verifying symmetric signatures, use a constant time comparison function to prevent oracle attacks.
- When verifying asymmetric signatures, use the standard verification functions, and don't assume signatures can be compared like symmetric ones.
- Make sure to verify the `webhook-timestamp` header has a timestamp that is within some allowable tolerance of the current timestamp to prevent replay attacks.
- Use the `webhook-id` header as an idempotency key to prevent accidentally processing the same webhook more than once (e.g. save the IDs in redis for 5 minutes).

### Operational considerations

The previous section covered important considerations relating to the signature scheme, the payload, and the headers. This section is about operational considerations required for a good webhook experience.

#### Event types

Event types indicate the type of the event being sent in the webhook and the schema of the payload. A payload associated with an event type should always have the same schema. You can think of event types as different URL paths in the case of REST. The same way that REST APIs always expect (and return) a set schema for a specific URL, so should your webhooks.

It's recommended that event types be formatted as an hierarchical, and full-stop delimited, list of identifiers, and that the identifiers would be limited to a limited set of characters `[a-zA-Z0-9_]`. This refers to the event type IDs used by the API, but doesn't limit the use of more user-friendly friendly display strings. For example, one could use `user.created` as the event type, and "A user has been created" as the event display string.

It is also recommended to let webhook consumers choose which event types they would like to receive for which endpoints, and do the filtering on the producing end. This reduces a lot of unnecessary load on the consumer, receiving events they have no interest in receiving.

#### Deliverability and reliability

In order for webhook implementations to be trusted and relied upon, they have to do whatever is possible to ensure the timely and reliable delivery of webhooks.

Webhook sending may sometimes fail. This can be due to networking issues, bugs in the receiver, or a variety of other issues. It's therefore up to the webhook producer to retry sending the webhook until a successful attempt or until it's determined that delivery may not be possible. Retries are an important part of having reliable webhooks.

It's recommended to retry delivery following a retry schedule spanning multiple days, with an exponential backoff. It's recommended to also add some level of random jitter to retries to prevent cases where the failures are due to recurring load caused by the webhook attempts themselves.

In some cases, webhook delivery may fail consistently over a long period of time. In that scenario it is important to both: notify the consumers using other channels (e.g. email), and is recommended to disable future delivery to the endpoint.

Example retry schedule:

| Delay       | Time since start |
| ----------- | ---------------- |
| Immediately | 00:00:00         |
| 5 seconds   | 00:00:05         |
| 5 minutes   | 00:05:05         |
| 30 minutes  | 00:35:05         |
| 2 hours     | 02:35:05         |
| 5 hours     | 07:35:05         |
| 10 hours    | 17:35:05         |
| 14 hours    | 31:35:05         |
| 20 hours    | 51:35:05         |
| 24 hours    | 75:35:05         |

#### Delivery success and failure

A webhook delivery is considered successful if it was responded to with a `2xx` status code (status codes 200-299), and it is considered a failure in any other scenario. Example failure scenarios include non-`2xx` response status codes (e.g: 404 and 500), request timeouts (see next section), connection resets, and more.

It's important to follow HTTP etiquette when sending webhooks, and respond to HTTP status codes appropriately. Here is the suggested status code handling:

- `2xx`: Success.
- `3xx`: Failure. Following redirects causes unnecessary load on both the sender and the receiver, it's therefore recommended to update the webhook URL instead.
- `410 Gone`: This is an indication by the server that it's no longer interested in receiving webhooks from this source. Sender should disable the webhook endpoint, and stop sending it messages.
- `429 Too Many Requests`: This indicates a rate-limit has been met, and it's recommended to throttle additional requests.
- `502 Bad Gateway` and `504 Gateway Timeout`: Both errors usually indicate that the server is under load, and it's recommended to throttle the requests.
- The rest of the status codes should be treated as a failure.

Additionally, some responses may also include a `Retry-After` header (e.g. `503 Service Unavailable`), which should be taken into consideration when scheduling the next attempt.

#### Request timeouts

In order to ensure the reliable delivery of webhooks it's important to ensure consumers have enough time to process and acknowledge the processing of requests. A recommended request timeout value for webhooks is somewhere between 15 and 30s.

#### Enforcing HTTPS

Depending on the content of the webhooks being sent, it may be advisable to ensure that all webhook endpoints are HTTPs. While the signature scheme above covers the authenticity and validity of the payloads (so they can't be tampered with), it doesn't encrypt the data, which means it may be possible to eavesdrop and view the content of the payloads.

#### Static source IPs

Some webhook consumers have firewalls (or other security mechanisms) in front of their webhook endpoints, and require webhooks to be sent from a predefined list of static IPs that can be allowed to go through the firewall. This is common in many corporate environments, and while not strictly a requirement for webhooks, it's a common consideration.

#### Server side request forgery (SSRF)

A server-side request forgery (SSRF) attack is when an attacker abuses functionality on the server to read or update internal resources. In the attack, the attacker supplies or modifies a URL which the server will then make a call to. By carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services which are not intended to be exposed.

Webhooks implementations are especially vulnerable to SSRF as they let their consumers (customers) add any URLs they want, which will be called from the internal webhook system.

The main way to protect against SSRF is to prevent the webhooks from calling into internal networks and services. To achieve this you'd want to do two things: the first would be to proxy all webhook requests through a special proxy (like[  smokescreen](https://github.com/stripe/smokescreen)) that filters internal IP addresses, and the second would be to put the webhook workers (or proxy) in their own private subnet that can't access internal services.

### Additional functionality

This section describes additional functionality that is not a core requirement for a webhook implementation but provide significant benefits to webhook producers and consumers.

#### Multiple endpoints (fanout)

It's common for webhook consumers to want to consume webhooks in multiple locations. For example, they may want to consume a `invoice.paid` event in their user management system (to unlock functionality for the customer), in their CRM (to update the sales team), and their team's communication application (to celebrate with the team). It's therefore recommended to enable customers to add multiple webhook endpoints so that they can receive the same webhook to multiple destinations.

#### Visibility into failures and manual retries

Webhooks can fail for a variety of reasons, and without good visibility into the failures, consumers can often be left unable to debug a service degradation or outage. This is why it is common for webhook producers to provide a way for their customers to list failed messages, and review the reasons for the failures. Additionally, it's immensely important to give consumers a way to manually replay specific webhooks or failures within a range in order to recover from long outages without missing message delivery.

#### Endpoint management API

Having an API to add, remove, and list webhook endpoints enables both webhook consumers and third party developers to build automation on top of webhooks. One common use-case, for example, is to have a workflow automation tool automatically add webhook endpoints with specific event types as users add and remove workflow triggers.

## Migrating to Standard Webhooks

Standard Webhooks can be supported in tandem with existing legacy webhook implementations and signature schemes with zero interruption to consumer workflow and running integrations.

In order to migrate to Standard Webhooks, just follow the signature scheme as outlined above and add the Standard Webhooks headers in addition to any existing headers you may already have. Adding additional headers without removing the existing ones will prevent any disruption to existing service. You can even reuse existing webhook signing secrets between the legacy scheme and Standard Webhooks, so even the secrets can remain the same.

The rest of the recommendations and requirements outlined in this document can too be added side by side with existing implementations without interfering.

### Migrating the payload

While migrating the payload is optional, and you can get most of the benefits of standard webhooks compatibility even without doing that. However, doing so will enable you to utilize even more of the standard webhooks ecosystem, and is therefore recommended.

There are a few strategies for migrating the payloads, each with its own advantages and disadvantages. The first is adding data to existing payloads with the wanted format. This approach is easy and backwards compatible, but it may lead to confusion, and it will also lead to redundancy in data. The second is a slightly better variation, where you still duplicate the data, but only for endpoints created before the switch-over date. The last alternative is to create a new event type for each of the existing ones, and have them conform to the new format.
