import * as base64 from "@stablelib/base64";
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
  // another realm (e.g. a test runner's VM context) is still accepted.
  if (ArrayBuffer.isView(payload)) {
    return new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
  }
  throw new Error("Expected payload to be of type string, Buffer or Uint8Array.");
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
    const jsonParse = options?.jsonParse ?? true;

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

    const timestamp = this.verifyTimestamp(msgTimestamp);

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

  /** Sign `payload` for the given message id and timestamp.
   *
   * A `Buffer` or `Uint8Array` payload is signed byte for byte, so binary (non-UTF-8) bodies
   * are signed as sent. A string is signed as its UTF-8 encoding.
   */
  public sign(msgId: string, timestamp: Date, payload: string | Uint8Array): string {
    const bytes = payloadBytes(payload);
    const timestampNumber = Math.floor(timestamp.getTime() / 1000);
    const prefix = new TextEncoder().encode(`${msgId}.${timestampNumber}.`);
    const toSign = new Uint8Array(prefix.length + bytes.length);
    toSign.set(prefix);
    toSign.set(bytes, prefix.length);
    const expectedSignature = base64.encode(sha256.hmac(this.key, toSign));
    return `v1,${expectedSignature}`;
  }

  private verifyTimestamp(timestampHeader: string): Date {
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
}
