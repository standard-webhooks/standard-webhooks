import * as base64 from "@stablelib/base64";
import * as sha256 from "fast-sha256";
import * as ed25519 from "@stablelib/ed25519";

import { Webhook, WebhookVerificationError } from "./index";

const defaultMsgID = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const defaultPayload = `{"test": 2432232314}`;
const defaultSecret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

const tolerance_in_ms = 5 * 60 * 1000;

const encoder = new TextEncoder();

class TestPayload {
  public id: string;
  public timestamp: number;
  public header: Record<string, string>;
  public secret: string;
  public payload: string;
  public signature: string;

  public constructor(timestamp = Date.now()) {
    this.id = defaultMsgID;
    this.timestamp = Math.floor(timestamp / 1000);

    this.payload = defaultPayload;
    this.secret = defaultSecret;

    const toSign = encoder.encode(`${this.id}.${this.timestamp}.${this.payload}`);
    this.signature = base64.encode(sha256.hmac(base64.decode(this.secret), toSign));

    this.header = {
      "webhook-id": this.id,
      "webhook-signature": "v1," + this.signature,
      "webhook-timestamp": this.timestamp.toString(),
    };
  }
}

// Deterministic ed25519 fixture keypair (seed 0x01 repeated) so signature expectations are stable.
const asymmetricSeed = Uint8Array.from({ length: 32 }, () => 1);
const asymmetricKeyPair = ed25519.generateKeyPairFromSeed(asymmetricSeed);
const privateKey = "whsk_" + base64.encode(asymmetricKeyPair.secretKey);
const publicKey = "whpk_" + base64.encode(asymmetricKeyPair.publicKey);

class AsymmetricTestPayload {
  public id: string;
  public timestamp: number;
  public header: Record<string, string>;
  public payload: string;
  public signature: string;

  public constructor(timestamp = Date.now()) {
    this.id = defaultMsgID;
    this.timestamp = Math.floor(timestamp / 1000);
    this.payload = defaultPayload;

    const toSign = encoder.encode(`${this.id}.${this.timestamp}.${this.payload}`);
    this.signature = base64.encode(ed25519.sign(asymmetricKeyPair.secretKey, toSign));

    this.header = {
      "webhook-id": this.id,
      "webhook-signature": "v1a," + this.signature,
      "webhook-timestamp": this.timestamp.toString(),
    };
  }
}

test("empty key raises error", () => {
  expect(() => {
    new Webhook("");
  }).toThrow(Error);
  expect(() => {
    new Webhook(undefined as any);
  }).toThrow(Error);
  expect(() => {
    new Webhook(null as any);
  }).toThrow(Error);
  expect(() => {
    new Webhook("whsec_");
  }).toThrow(Error);
  expect(() => {
    new Webhook("whsk_");
  }).toThrow(Error);
  expect(() => {
    new Webhook("whpk_");
  }).toThrow(Error);
});

test("missing id raises error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  delete testPayload.header["webhook-id"];

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("missing timestamp raises error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  delete testPayload.header["webhook-timestamp"];

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("invalid timestamp throws error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  testPayload.header["webhook-timestamp"] = "hello";

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("missing signature raises error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  delete testPayload.header["webhook-signature"];

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("invalid signature throws error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  testPayload.header["webhook-signature"] = "v1,dawfeoifkpqwoekfpqoekf";

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("partial signature throws error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  testPayload.header["webhook-signature"] = testPayload.header["webhook-signature"].slice(
    0,
    8
  );

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);

  testPayload.header["webhook-signature"] = "v1,";

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("valid signature is valid and returns valid json", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();

  wh.verify(testPayload.payload, testPayload.header);
});

test("valid unbranded signature is valid and returns valid json", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  const unbrandedHeaders: Record<string, string> = {
    "webhook-id": testPayload.header["webhook-id"],
    "webhook-signature": testPayload.header["webhook-signature"],
    "webhook-timestamp": testPayload.header["webhook-timestamp"],
  };
  testPayload.header = unbrandedHeaders;

  wh.verify(testPayload.payload, testPayload.header);
});

test("old timestamp fails", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload(Date.now() - tolerance_in_ms - 1000);

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("new timestamp fails", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload(Date.now() + tolerance_in_ms + 1000);

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("multi sig payload is valid", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  const sigs = [
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    "v1a,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    testPayload.header["webhook-signature"], // valid signature
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
  ];
  testPayload.header["webhook-signature"] = sigs.join(" ");

  wh.verify(testPayload.payload, testPayload.header);
});

test("verification works with and without signature prefix", () => {
  const testPayload = new TestPayload();

  let wh = new Webhook(defaultSecret);
  wh.verify(testPayload.payload, testPayload.header);

  wh = new Webhook("whsec_" + defaultSecret);
  wh.verify(testPayload.payload, testPayload.header);
});

test("sign function works", () => {
  const key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
  const msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
  const timestamp = new Date(1614265330 * 1000);
  const payload = '{"test": 2432232314}';
  const expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

  const wh = new Webhook(key);

  const signature = wh.sign(msgId, timestamp, payload);
  expect(signature).toBe(expected);
});

test("empty payload returns undefined", () => {
  const wh = new Webhook(defaultSecret);

  const msgId = defaultMsgID;
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = "";

  const toSign = encoder.encode(`${msgId}.${timestamp}.${payload}`);
  const signature = base64.encode(sha256.hmac(base64.decode(defaultSecret), toSign));

  const header = {
    "webhook-id": msgId,
    "webhook-signature": "v1," + signature,
    "webhook-timestamp": timestamp.toString(),
  };

  const result = wh.verify(payload, header);
  expect(result).toBeUndefined();
});

// v1a (asymmetric, ed25519) tests

test("v1a: empty key raises error", () => {
  expect(() => {
    new Webhook("whsk_");
  }).toThrow(Error);
  expect(() => {
    new Webhook("whpk_");
  }).toThrow(Error);
});

test("v1a: valid signature is valid and returns valid json", () => {
  const wh = new Webhook(publicKey);

  const testPayload = new AsymmetricTestPayload();

  wh.verify(testPayload.payload, testPayload.header);
});

test("v1a: invalid signature throws error", () => {
  const wh = new Webhook(publicKey);

  const testPayload = new AsymmetricTestPayload();
  testPayload.header["webhook-signature"] = "v1a,dawfeoifkpqwoekfpqoekf";

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("v1a: tampered signature throws error", () => {
  const wh = new Webhook(publicKey);

  const testPayload = new AsymmetricTestPayload();
  const otherSeed = Uint8Array.from({ length: 32 }, () => 2);
  const otherKeyPair = ed25519.generateKeyPairFromSeed(otherSeed);
  const toSign = encoder.encode(
    `${testPayload.id}.${testPayload.timestamp}.${testPayload.payload}`
  );
  const wrongSignature = base64.encode(ed25519.sign(otherKeyPair.secretKey, toSign));
  testPayload.header["webhook-signature"] = "v1a," + wrongSignature;

  expect(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("v1a: a v1-keyed instance ignores v1a signatures and vice versa", () => {
  const symmetricWh = new Webhook(defaultSecret);
  const asymmetricWh = new Webhook(publicKey);

  const symmetricPayload = new TestPayload();
  const asymmetricPayload = new AsymmetricTestPayload();

  expect(() => {
    asymmetricWh.verify(symmetricPayload.payload, symmetricPayload.header);
  }).toThrow(WebhookVerificationError);

  expect(() => {
    symmetricWh.verify(asymmetricPayload.payload, asymmetricPayload.header);
  }).toThrow(WebhookVerificationError);
});

test("v1a: verifies the matching signature out of a mixed v1/v1a header", () => {
  const testPayload = new AsymmetricTestPayload();
  const sigs = [
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    testPayload.header["webhook-signature"], // valid v1a signature
  ];
  testPayload.header["webhook-signature"] = sigs.join(" ");

  const wh = new Webhook(publicKey);
  wh.verify(testPayload.payload, testPayload.header);
});

test("v1a: sign function works", () => {
  const msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
  const timestamp = new Date(1614265330 * 1000);
  const payload = '{"test": 2432232314}';
  const expected =
    "v1a,Ykcu7AtGZGmZxFEH1Gaa2Nd7feY/CTuruoL4fqgnKwfbHU4DhemoVHZdvGfIvKvn4BIgwktLGGPGIr/i9nK7AA==";

  const wh = new Webhook(privateKey);
  const signature = wh.sign(msgId, timestamp, payload);
  expect(signature).toBe(expected);
});

test("v1a: signing with a public key throws", () => {
  const wh = new Webhook(publicKey);

  expect(() => {
    wh.sign(defaultMsgID, new Date(), defaultPayload);
  }).toThrow(Error);
});

test("v1a: empty payload returns undefined", () => {
  const wh = new Webhook(publicKey);

  const msgId = defaultMsgID;
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = "";

  const toSign = encoder.encode(`${msgId}.${timestamp}.${payload}`);
  const signature = base64.encode(ed25519.sign(asymmetricKeyPair.secretKey, toSign));

  const header = {
    "webhook-id": msgId,
    "webhook-signature": "v1a," + signature,
    "webhook-timestamp": timestamp.toString(),
  };

  const result = wh.verify(payload, header);
  expect(result).toBeUndefined();
});
