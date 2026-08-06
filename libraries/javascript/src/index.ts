import { timingSafeEqual } from "./timing_safe_equal";
import * as base64 from "@stablelib/base64";
import * as sha256 from "fast-sha256";
import * as ed25519 from "@stablelib/ed25519";

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

type Scheme = "v1" | "v1a";
type AsymmetricKeyRole = "private" | "public";

export class Webhook {
  private static secretPrefix = "whsec_";
  private static privateKeyPrefix = "whsk_";
  private static publicKeyPrefix = "whpk_";
  private readonly key: Uint8Array;
  private readonly scheme: Scheme;
  private readonly asymmetricKeyRole?: AsymmetricKeyRole;

  constructor(secret: string | Uint8Array, options?: WebhookOptions) {
    if (options?.format === "raw") {
      if (secret instanceof Uint8Array) {
        this.key = secret;
      } else {
        this.key = Uint8Array.from(secret, (c) => c.charCodeAt(0));
      }
      this.scheme = "v1";
    } else {
      if (typeof secret !== "string") {
        throw new Error("Expected secret to be of type string");
      }
      if (secret.startsWith(Webhook.privateKeyPrefix)) {
        this.key = base64.decode(secret.substring(Webhook.privateKeyPrefix.length));
        this.scheme = "v1a";
        this.asymmetricKeyRole = "private";
      } else if (secret.startsWith(Webhook.publicKeyPrefix)) {
        this.key = base64.decode(secret.substring(Webhook.publicKeyPrefix.length));
        this.scheme = "v1a";
        this.asymmetricKeyRole = "public";
      } else {
        if (secret.startsWith(Webhook.secretPrefix)) {
          secret = secret.substring(Webhook.secretPrefix.length);
        }
        this.key = base64.decode(secret);
        this.scheme = "v1";
      }
    }
    if (!this.key || this.key.length === 0) {
      throw new Error("Secret can't be empty.");
    }
  }

  public verify(
    payload: string | Buffer,
    headers_: WebhookUnbrandedRequiredHeaders | Record<string, string>
  ): unknown {
    const headers: Record<string, string> = {};
    for (const key of Object.keys(headers_)) {
      headers[key.toLowerCase()] = (headers_ as Record<string, string>)[key];
    }

    const msgId = headers["webhook-id"];
    const msgSignature = headers["webhook-signature"];
    const msgTimestamp = headers["webhook-timestamp"];

    if (!msgSignature || !msgId || !msgTimestamp) {
      throw new WebhookVerificationError("Missing required headers");
    }

    const timestamp = this.verifyTimestamp(msgTimestamp);

    if (typeof payload !== "string" && payload.constructor.name !== "Buffer") {
      throw new Error("Expected payload to be of type string or Buffer.");
    }
    const payloadString = payload.toString();

    const encoder = new globalThis.TextEncoder();
    const timestampNumber = Math.floor(timestamp.getTime() / 1000);
    const toSign = encoder.encode(`${msgId}.${timestampNumber}.${payloadString}`);

    const passedSignatures = msgSignature.split(" ");

    for (const versionedSignature of passedSignatures) {
      const [version, signature] = versionedSignature.split(",");
      if (version !== this.scheme || !signature) {
        continue;
      }

      if (this.scheme === "v1") {
        const expectedSignature = base64.encode(sha256.hmac(this.key, toSign));
        if (timingSafeEqual(encoder.encode(signature), encoder.encode(expectedSignature))) {
          if (payloadString === "") {
            return undefined;
          }
          return JSON.parse(payloadString);
        }
      } else {
        try {
          const decodedSignature = base64.decode(signature);
          if (ed25519.verify(this.key, toSign, decodedSignature)) {
            if (payloadString === "") {
              return undefined;
            }
            return JSON.parse(payloadString);
          }
        } catch {
          continue;
        }
      }
    }
    throw new WebhookVerificationError("No matching signature found");
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

    if (this.scheme === "v1a") {
      if (this.asymmetricKeyRole !== "private") {
        throw new Error(
          "Cannot sign with a public key. Provide a whsk_ private key to sign webhooks."
        );
      }
      const expectedSignature = base64.encode(ed25519.sign(this.key, toSign));
      return `v1a,${expectedSignature}`;
    }

    const expectedSignature = base64.encode(sha256.hmac(this.key, toSign));
    return `v1,${expectedSignature}`;
  }

  private verifyTimestamp(timestampHeader: string): Date {
    const now = Math.floor(Date.now() / 1000);
    const timestamp = parseInt(timestampHeader, 10);
    if (isNaN(timestamp)) {
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
