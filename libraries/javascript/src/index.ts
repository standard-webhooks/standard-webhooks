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
   * @returns After successful verification: if `options.jsonParse` is `true`, returns the
   *     JSON-parsed input data; if `options.jsonParse` is `false`, returns `undefined`
   * @throws `WebhookVerificationError` if one of the required headers is missing,
   *     invalid, too old or too new; or no matching signatures is found
   */
  public verify(
    payload: string | Buffer,
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

    const encoder = new globalThis.TextEncoder();
    const expectedSignature = encoder.encode(this.sign(msgId, timestamp, payload));

    const passedSignatures = msgSignature.split(" ");
    if (
      !passedSignatures.some((versionedSignature) =>
        timingSafeEqual(encoder.encode(versionedSignature), expectedSignature)
      )
    ) {
      throw new WebhookVerificationError("No matching signature found");
    }

    const payloadString = payload.toString();
    if (payloadString === "") {
      return undefined;
    }
    if (jsonParse) {
      return JSON.parse(payloadString);
    } else {
      return undefined;
    }
  }

  public sign(msgId: string, timestamp: Date, payload: string | Buffer): string {
    if (typeof payload === "string") {
      // Do nothing, already a string
    } else if (payload.constructor.name === "Buffer") {
      payload = payload.toString();
    } else {
      throw new Error("Expected payload to be of type string or Buffer.");
    }

    const encoder = new TextEncoder();
    const timestampNumber = Math.floor(timestamp.getTime() / 1000);
    const toSign = encoder.encode(`${msgId}.${timestampNumber}.${payload}`);
    const expectedSignature = base64.encode(sha256.hmac(this.key, toSign));
    return `v1,${expectedSignature}`;
  }

  /** Calculate the response to an endpoint verification challenge.
   *
   * @param challenge The value of the `webhook-challenge` request header
   * @returns The value for the `webhook-challenge-response` response header
   */
  public endpointVerificationResponse(challenge: string): string {
    const encoder = new TextEncoder();
    const verificationKey = sha256.hmac(this.key, encoder.encode("wev-v1"));
    const signature = base64.encode(
      sha256.hmac(verificationKey, encoder.encode(challenge))
    );
    return `v1,${signature}`;
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
