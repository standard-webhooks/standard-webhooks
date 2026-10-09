import * as assert from "node:assert/strict";
import { test } from "node:test";
import * as vm from "node:vm";
import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";
import * as sha256 from "fast-sha256";

import { Webhook, WebhookVerificationError } from "./index";

const defaultMsgID = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const defaultPayload = `{"test": 2432232314}`;
const defaultSecret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const defaultSecretKey = base64.decode(defaultSecret.slice("whsec_".length));

const tolerance_in_ms = 5 * 60 * 1000;

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

    const toSign = utf8.encode(`${this.id}.${this.timestamp}.${this.payload}`);
    this.signature = base64.encode(sha256.hmac(defaultSecretKey, toSign));

    this.header = {
      "webhook-id": this.id,
      "webhook-signature": `v1,${this.signature}`,
      "webhook-timestamp": this.timestamp.toString(),
    };
  }
}

test("empty key raises error", () => {
  assert.throws(() => {
    new Webhook("");
  }, Error);
  assert.throws(() => {
    new Webhook(undefined as any);
  }, Error);
  assert.throws(() => {
    new Webhook(null as any);
  }, Error);
  assert.throws(() => {
    new Webhook("whsec_");
  }, Error);
});

test("missing id raises error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  delete testPayload.header["webhook-id"];

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("missing timestamp raises error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  delete testPayload.header["webhook-timestamp"];

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("invalid timestamp throws error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  testPayload.header["webhook-timestamp"] = "hello";

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("missing signature raises error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  delete testPayload.header["webhook-signature"];

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("invalid signature throws error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  testPayload.header["webhook-signature"] = "v1,dawfeoifkpqwoekfpqoekf";

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("partial signature throws error", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  testPayload.header["webhook-signature"] = testPayload.header["webhook-signature"].slice(
    0,
    8
  );

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);

  testPayload.header["webhook-signature"] = "v1,";

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("valid signature is valid and returns valid json", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
  const testPayload = new TestPayload();

  const result = wh.verify(testPayload.payload, testPayload.header);
  assert.deepStrictEqual(result, { test: 2432232314 });
});

test("valid signature is valid without returning json", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
  const testPayload = new TestPayload();

  const result = wh.verify(testPayload.payload, testPayload.header, { jsonParse: false });
  assert.strictEqual(result, undefined);
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

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("new timestamp fails", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload(Date.now() + tolerance_in_ms + 1000);

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("multi sig payload is valid", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  const sigs = [
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    testPayload.header["webhook-signature"], // valid signature
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
  ];
  testPayload.header["webhook-signature"] = sigs.join(" ");

  wh.verify(testPayload.payload, testPayload.header);
});

test("malformed signatures are skipped", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  const sigs = [
    "v1",
    "v1,not-base64!",
    testPayload.header["webhook-signature"], // valid signature
  ];
  testPayload.header["webhook-signature"] = sigs.join(" ");

  wh.verify(testPayload.payload, testPayload.header);
});

test("valid signature with an unknown version fails", () => {
  const wh = new Webhook("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const testPayload = new TestPayload();
  testPayload.header["webhook-signature"] = `v2,${testPayload.signature}`;

  assert.throws(() => {
    wh.verify(testPayload.payload, testPayload.header);
  }, WebhookVerificationError);
});

test("verification works with and without signature prefix", () => {
  const testPayload = new TestPayload();

  let wh = new Webhook(defaultSecret.slice("whsec_".length));
  wh.verify(testPayload.payload, testPayload.header);

  wh = new Webhook(defaultSecret);
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
  assert.equal(signature, expected);
});

test("empty payload returns undefined", () => {
  const wh = new Webhook(defaultSecret);

  const msgId = defaultMsgID;
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = "";

  const toSign = utf8.encode(`${msgId}.${timestamp}.${payload}`);
  const signature = base64.encode(sha256.hmac(defaultSecretKey, toSign));

  const header = {
    "webhook-id": msgId,
    "webhook-signature": `v1,${signature}`,
    "webhook-timestamp": timestamp.toString(),
  };

  const result = wh.verify(payload, header);
  assert.equal(result, undefined);
});

// Every byte value, so the payload is not valid UTF-8. The expected signature is the Go
// library's for the same inputs, which signs the payload bytes as given.
const binaryPayload = Uint8Array.from({ length: 256 }, (_, i) => i);
const binaryPayloadSignature = "v1,sEcZ042G8Crqgxbybb3y0eDxQR3TcfYsk11I1XULhSI=";
const signTimestamp = new Date(1614265330 * 1000);

// Headers for `payload` signed now. sign() itself is checked against the known-answer
// vectors above, so the verify tests can use it.
function signedHeader(wh: Webhook, payload: string | Uint8Array): Record<string, string> {
  const timestamp = new Date();
  return {
    "webhook-id": defaultMsgID,
    "webhook-signature": wh.sign(defaultMsgID, timestamp, payload),
    "webhook-timestamp": Math.floor(timestamp.getTime() / 1000).toString(),
  };
}

test("sign signs a binary payload byte for byte", () => {
  const wh = new Webhook(defaultSecret);

  assert.equal(
    wh.sign(defaultMsgID, signTimestamp, binaryPayload),
    binaryPayloadSignature
  );
  assert.equal(
    wh.sign(defaultMsgID, signTimestamp, Buffer.from(binaryPayload)),
    binaryPayloadSignature
  );
});

test("sign signs only the bytes of a Uint8Array view", () => {
  const wh = new Webhook(defaultSecret);
  const padded = new Uint8Array(binaryPayload.length + 4);
  padded.set(binaryPayload, 2);

  assert.equal(
    wh.sign(defaultMsgID, signTimestamp, padded.subarray(2, 2 + binaryPayload.length)),
    binaryPayloadSignature
  );
});

test("sign gives the same signature for a string and its UTF-8 bytes", () => {
  const wh = new Webhook(defaultSecret);
  const payload = '{"test": "ünïcödé ✓"}';

  assert.equal(
    wh.sign(defaultMsgID, signTimestamp, Buffer.from(payload)),
    wh.sign(defaultMsgID, signTimestamp, payload)
  );
  assert.equal(
    wh.sign(defaultMsgID, signTimestamp, new TextEncoder().encode(payload)),
    wh.sign(defaultMsgID, signTimestamp, payload)
  );
});

test("sign accepts a Uint8Array from another realm", () => {
  const wh = new Webhook(defaultSecret);
  const foreign = vm.runInNewContext(
    "new Uint8Array(256).map((_, i) => i)"
  ) as Uint8Array;
  assert.equal(foreign instanceof Uint8Array, false);

  assert.equal(wh.sign(defaultMsgID, signTimestamp, foreign), binaryPayloadSignature);
});

test("sign rejects a payload that is not a string or bytes", () => {
  const wh = new Webhook(defaultSecret);

  assert.throws(() => {
    wh.sign(defaultMsgID, signTimestamp, { test: 1 } as any);
  }, Error);
  assert.throws(() => {
    wh.sign(defaultMsgID, signTimestamp, Uint16Array.from([1, 2]) as any);
  }, Error);
  assert.throws(() => {
    wh.sign(defaultMsgID, signTimestamp, new DataView(binaryPayload.buffer) as any);
  }, Error);
});

test("binary payload is valid", () => {
  const wh = new Webhook(defaultSecret);
  const header = signedHeader(wh, binaryPayload);

  assert.equal(wh.verify(binaryPayload, header, { jsonParse: false }), undefined);
  assert.equal(
    wh.verify(Buffer.from(binaryPayload), header, { jsonParse: false }),
    undefined
  );
});

test("binary payload with a changed byte fails", () => {
  const wh = new Webhook(defaultSecret);
  const header = signedHeader(wh, binaryPayload);
  const changed = Uint8Array.from(binaryPayload);
  changed[255] = 0;

  assert.throws(() => {
    wh.verify(changed, header, { jsonParse: false });
  }, WebhookVerificationError);
});

test("JSON payload as Uint8Array is valid and returns valid json", () => {
  const wh = new Webhook(defaultSecret);
  const testPayload = new TestPayload();

  const json = wh.verify(
    new TextEncoder().encode(testPayload.payload),
    testPayload.header
  );
  assert.deepEqual(json, { test: 2432232314 });
});

test("JSON payload as Uint8Array with a UTF-8 BOM returns valid json", () => {
  const wh = new Webhook(defaultSecret);
  const json = new TextEncoder().encode('{"test": 2432232314}');
  const payload = new Uint8Array([0xef, 0xbb, 0xbf, ...json]);

  // The BOM is signed like any other bytes; only the JSON parse skips it.
  assert.deepEqual(wh.verify(payload, signedHeader(wh, payload)), {
    test: 2432232314,
  });
  assert.throws(() => {
    wh.verify(json, signedHeader(wh, payload));
  }, WebhookVerificationError);
});

test("empty Uint8Array payload returns undefined", () => {
  const wh = new Webhook(defaultSecret);
  const payload = new Uint8Array();

  assert.equal(wh.verify(payload, signedHeader(wh, payload)), undefined);
});

test("challenge response matches test vector", () => {
  const wh = new Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  const result = wh.challengeResponse("0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=");
  assert.equal(result, "v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M=");
});

test("verify challenge response accepts test vector", () => {
  const wh = new Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  wh.verifyChallengeResponse(
    "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=",
    "v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M="
  );
});

test("verify challenge response rejects wrong challenge", () => {
  const wh = new Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  assert.throws(() => {
    wh.verifyChallengeResponse(
      "1njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=",
      "v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M="
    );
  }, WebhookVerificationError);
});

test("verify challenge response rejects lists", () => {
  const wh = new Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

  assert.throws(() => {
    wh.verifyChallengeResponse(
      "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=",
      "v2,abc v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M="
    );
  }, WebhookVerificationError);
});

test("challenge response depends on the secret", () => {
  const wh = new Webhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSx");

  const result = wh.challengeResponse("0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=");
  assert.notEqual(result, "v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M=");
});
