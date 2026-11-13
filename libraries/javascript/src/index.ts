import * as base64 from "@stablelib/base64";
import * as ed25519 from "@stablelib/ed25519";
import * as sha256 from "fast-sha256";
import { timingSafeEqual } from "./timing_safe_equal";

const WEBHOOK_TOLERANCE_IN_SECONDS = 5 * 60; // 5 minutes

class ExtendableError extends Error {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ExtendableError.prototype);
    this.name = "ExtendableError";
    this.stack = new Error(message).stack;
  }
}

export class WebhookVerificationError extends ExtendableError {
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, WebhookVerificationError.prototype);
    this.name = "WebhookVerificationError";
  }
}

export interface WebhookUnbrandedRequiredHeaders {
  "webhook-id": string;
  "webhook-timestamp": string;
  "webhook-signature": string;
}

export interface WebhookOptions {
  format?: "raw";
}

export interface VerifyOptions {
  /** Whether to parse the payload as JSON on success (default: true) */
  jsonParse?: boolean;
}

/** The payload as signed: the body bytes exactly as received. A string is encoded as UTF-8. */
function payloadBytes(payload: string | Uint8Array): Uint8Array {
  if (typeof payload === "string") {
    return new TextEncoder().encode(payload);
  }
  // `ArrayBuffer.isView` rather than `instanceof Uint8Array`, so a Buffer or Uint8Array from
  // another realm (e.g. a test runner's VM context) is still accepted. Only byte views: a
  // DataView or a wider typed array (e.g. Uint16Array) is rejected rather than signed as its
  // platform-endian underlying bytes.
  if (ArrayBuffer.isView(payload) && payload.BYTES_PER_ELEMENT === 1) {
    return new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
  }
  throw new Error("Expected payload to be of type string, Buffer or Uint8Array.");
}

/** Normalize the headers (case-insensitive names), and check the timestamp is in tolerance. */
function parseHeaders(
  headers: WebhookUnbrandedRequiredHeaders | Record<string, string>
): { msgId: string; msgSignature: string; timestamp: Date } {
  const normalizedHeaders: Record<string, string> = {};
  for (const key of Object.keys(headers)) {
    normalizedHeaders[key.toLowerCase()] = (headers as Record<string, string>)[key];
  }

  const msgId = normalizedHeaders["webhook-id"];
  const msgSignature = normalizedHeaders["webhook-signature"];
  const msgTimestamp = normalizedHeaders["webhook-timestamp"];

  if (!msgSignature || !msgId || !msgTimestamp) {
    throw new WebhookVerificationError("Missing required headers");
  }

  return { msgId, msgSignature, timestamp: verifyTimestamp(msgTimestamp) };
}

function verifyTimestamp(timestampHeader: string): Date {
  const now = Math.floor(Date.now() / 1000);
  const timestamp = parseInt(timestampHeader, 10);
  if (Number.isNaN(timestamp)) {
    throw new WebhookVerificationError("Invalid Signature Headers");
  }

  if (now - timestamp > WEBHOOK_TOLERANCE_IN_SECONDS) {
    throw new WebhookVerificationError("Message timestamp too old");
  }
  if (timestamp > now + WEBHOOK_TOLERANCE_IN_SECONDS) {
    throw new WebhookVerificationError("Message timestamp too new");
  }
  return new Date(timestamp * 1000);
}

/** The return value of `verify` after successful verification. */
function parsePayload(
  payload: string | Uint8Array,
  bytes: Uint8Array,
  options?: VerifyOptions
): unknown {
  const jsonParse = options?.jsonParse ?? true;
  if (bytes.length === 0) {
    return undefined;
  }
  if (jsonParse) {
    return JSON.parse(
      typeof payload === "string" ? payload : new TextDecoder().decode(bytes)
    );
  } else {
    return undefined;
  }
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a);
  ret.set(b, a.length);
  return ret;
}

/** The response to an endpoint verification challenge, for the given endpoint key. */
function challengeResponse(
  endpointKey: Uint8Array,
  challenge: string,
  identifier: string
): string {
  const encoder = new TextEncoder();
  const verificationKey = sha256.hmac(endpointKey, encoder.encode("wev-v1"));
  const signature = base64.encode(
    sha256.hmac(verificationKey, encoder.encode(challenge))
  );
  return `${identifier},${signature}`;
}

export class Webhook {
  private static prefix = "whsec_";
  private readonly key: Uint8Array;

  constructor(secret: string | Uint8Array, options?: WebhookOptions) {
    if (options?.format === "raw") {
      if (secret instanceof Uint8Array) {
        this.key = secret;
      } else {
        this.key = Uint8Array.from(secret, (c) => c.charCodeAt(0));
      }
    } else {
      if (typeof secret !== "string") {
        throw new Error("Expected secret to be of type string");
      }
      if (secret.startsWith(Webhook.prefix)) {
        secret = secret.substring(Webhook.prefix.length);
      }
      this.key = base64.decode(secret);
    }
    if (this.key.length === 0) {
      throw new Error("Secret can't be empty.");
    }
  }

  /** Verify the given webhook headers against the body bytes (payload).
   *
   * Pass the raw request body exactly as received: a `Buffer` or `Uint8Array` is signed byte
   * for byte, so binary (non-UTF-8) bodies verify. A string is signed as its UTF-8 encoding.
   *
   * @returns After successful verification: if `options.jsonParse` is `true`, returns the
   *     JSON-parsed input data; if `options.jsonParse` is `false`, returns `undefined`
   * @throws `WebhookVerificationError` if one of the required headers is missing,
   *     invalid, too old or too new; or no matching signatures is found
   */
  public verify(
    payload: string | Uint8Array,
    headers: WebhookUnbrandedRequiredHeaders | Record<string, string>,
    options?: VerifyOptions
  ): unknown {
    const { msgId, msgSignature, timestamp } = parseHeaders(headers);

    const bytes = payloadBytes(payload);
    const encoder = new globalThis.TextEncoder();
    const expectedSignature = encoder.encode(this.sign(msgId, timestamp, bytes));

    const passedSignatures = msgSignature.split(" ");
    if (
      !passedSignatures.some((versionedSignature) =>
        timingSafeEqual(encoder.encode(versionedSignature), expectedSignature)
      )
    ) {
      throw new WebhookVerificationError("No matching signature found");
    }

    return parsePayload(payload, bytes, options);
  }

  /** Sign `payload` for the given message id and timestamp.
   *
   * A `Buffer` or `Uint8Array` payload is signed byte for byte, so binary (non-UTF-8) bodies
   * are signed as sent. A string is signed as its UTF-8 encoding.
   */
  public sign(msgId: string, timestamp: Date, payload: string | Uint8Array): string {
    const bytes = payloadBytes(payload);
    const timestampNumber = Math.floor(timestamp.getTime() / 1000);
    const prefix = new TextEncoder().encode(`${msgId}.${timestampNumber}.`);
    const toSign = concatBytes(prefix, bytes);
    const expectedSignature = base64.encode(sha256.hmac(this.key, toSign));
    return `v1,${expectedSignature}`;
  }

  /** Calculate the response to an endpoint verification challenge.
   *
   * @param challenge The value of the `webhook-challenge` request header
   * @returns The value for the `webhook-challenge-response` response header
   */
  public endpointVerificationResponse(challenge: string): string {
    return challengeResponse(this.key, challenge, "v1");
  }

  /** Verify the response to an endpoint verification challenge.
   *
   * @param challenge The challenge sent in the `webhook-challenge` request header
   * @param header The value of the `webhook-challenge-response` response header
   * @throws `WebhookVerificationError` if no matching signature is found
   */
  public verifyEndpointVerificationResponse(challenge: string, header: string): void {
    if (!header) {
      throw new WebhookVerificationError("Missing challenge response");
    }

    const encoder = new globalThis.TextEncoder();
    const expectedSignature = encoder.encode(
      this.endpointVerificationResponse(challenge)
    );
    if (!timingSafeEqual(encoder.encode(header), expectedSignature)) {
      throw new WebhookVerificationError("No matching signature found");
    }
  }
}

/** Verify webhooks signed with asymmetric (`v2a`, ed25519) signatures.
 *
 * Only verification is supported: producers are expected to sign using a KMS or an HSM.
 */
export class WebhookAsymmetric {
  private static prefix = "whpk_";
  private readonly publicKeys: Uint8Array[];
  private readonly endpointId: string;

  /**
   * @param endpointId The endpoint ID the producer shared with you together with the
   *     public key. Never take it from the request.
   * @param publicKeys The producer's trusted public keys (`whpk_...`). Webhooks signed with
   *     any of them are accepted, so keys can be rotated by adding the new key to the list.
   *     The first key must be the newest one: it's the one used for endpoint verification.
   */
  constructor(endpointId: string, publicKeys: string[]) {
    if (!Array.isArray(publicKeys) || publicKeys.length === 0) {
      throw new Error("Public keys can't be empty.");
    }
    this.publicKeys = publicKeys.map((publicKey) => {
      if (typeof publicKey !== "string") {
        throw new Error("Expected public key to be of type string");
      }
      if (!publicKey.startsWith(WebhookAsymmetric.prefix)) {
        throw new Error(`Public key must start with "${WebhookAsymmetric.prefix}".`);
      }
      const key = base64.decode(publicKey.substring(WebhookAsymmetric.prefix.length));
      if (key.length !== ed25519.PUBLIC_KEY_LENGTH) {
        throw new Error(
          `Public key must be ${ed25519.PUBLIC_KEY_LENGTH} bytes, got ${key.length}.`
        );
      }
      return key;
    });
    if (typeof endpointId !== "string" || endpointId.length === 0) {
      throw new Error("Endpoint ID can't be empty.");
    }
    if (endpointId.includes(".")) {
      throw new Error('Endpoint ID can\'t contain ".".');
    }
    this.endpointId = endpointId;
  }

  /** Verify the given webhook headers against the body bytes (payload).
   *
   * Pass the raw request body exactly as received: a `Buffer` or `Uint8Array` is verified
   * byte for byte, so binary (non-UTF-8) bodies verify. A string is verified as its UTF-8
   * encoding.
   *
   * @returns After successful verification: if `options.jsonParse` is `true`, returns the
   *     JSON-parsed input data; if `options.jsonParse` is `false`, returns `undefined`
   * @throws `WebhookVerificationError` if one of the required headers is missing,
   *     invalid, too old or too new; or no matching signatures is found
   */
  public verify(
    payload: string | Uint8Array,
    headers: WebhookUnbrandedRequiredHeaders | Record<string, string>,
    options?: VerifyOptions
  ): unknown {
    const { msgId, msgSignature, timestamp } = parseHeaders(headers);

    const bytes = payloadBytes(payload);
    const timestampNumber = Math.floor(timestamp.getTime() / 1000);
    const prefix = new TextEncoder().encode(
      `${this.endpointId}.${msgId}.${timestampNumber}.`
    );
    const digest = sha256.hash(concatBytes(prefix, bytes));

    const found = msgSignature.split(" ").some((versionedSignature) => {
      if (!versionedSignature.startsWith("v2a,")) {
        return false;
      }
      let signature: Uint8Array;
      try {
        signature = base64.decode(versionedSignature.substring("v2a,".length));
      } catch {
        return false;
      }
      if (signature.length !== ed25519.SIGNATURE_LENGTH) {
        return false;
      }
      return this.publicKeys.some((publicKey) =>
        ed25519.verify(publicKey, digest, signature)
      );
    });
    if (!found) {
      throw new WebhookVerificationError("No matching signature found");
    }

    return parsePayload(payload, bytes, options);
  }

  /** Calculate the response to an endpoint verification challenge, using the first (newest)
   * public key.
   *
   * @param challenge The value of the `webhook-challenge` request header
   * @returns The value for the `webhook-challenge-response` response header
   */
  public endpointVerificationResponse(challenge: string): string {
    return this.challengeResponse(this.publicKeys[0], challenge);
  }

  /** Verify the response to an endpoint verification challenge. The response is accepted if
   * it matches any of the public keys.
   *
   * @param challenge The challenge sent in the `webhook-challenge` request header
   * @param header The value of the `webhook-challenge-response` response header
   * @throws `WebhookVerificationError` if no matching signature is found
   */
  public verifyEndpointVerificationResponse(challenge: string, header: string): void {
    if (!header) {
      throw new WebhookVerificationError("Missing challenge response");
    }

    const encoder = new globalThis.TextEncoder();
    const passed = encoder.encode(header);
    let found = false;
    for (const publicKey of this.publicKeys) {
      const expected = encoder.encode(this.challengeResponse(publicKey, challenge));
      // Not short-circuiting, so the time taken doesn't depend on which key matched.
      found = timingSafeEqual(passed, expected) || found;
    }
    if (!found) {
      throw new WebhookVerificationError("No matching signature found");
    }
  }

  private challengeResponse(publicKey: Uint8Array, challenge: string): string {
    const endpointKey = concatBytes(
      publicKey,
      new TextEncoder().encode(`.${this.endpointId}`)
    );
    return challengeResponse(endpointKey, challenge, "v2a");
  }
}
