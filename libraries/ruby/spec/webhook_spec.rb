# frozen_string_literal: true

require "standardwebhooks"

DEFAULT_MSG_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
DEFAULT_PAYLOAD = '{"test": 2432232314}'
DEFAULT_SECRET = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
TOLERANCE = 5 * 60

class TestPayload
  attr_accessor :secret
  attr_accessor :id
  attr_accessor :timestamp
  attr_accessor :payload
  attr_accessor :signature
  attr_accessor :headers

  def initialize(timestamp = Time.now.to_i)
    @secret = DEFAULT_SECRET

    @id = DEFAULT_MSG_ID
    @timestamp = timestamp

    @payload = DEFAULT_PAYLOAD
    @secret = DEFAULT_SECRET

    toSign = "#{@id}.#{@timestamp}.#{@payload}"
    @signature = Base64.encode64(
      OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), Base64.decode64(DEFAULT_SECRET), toSign)
    ).strip

    @headers = {
      "webhook-id" => @id,
      "webhook-signature" => "v1,#{@signature}",
      "webhook-timestamp" => @timestamp
    }
  end
end

describe StandardWebhooks::Webhook do
  describe ".new" do
    it "rejects empty webhook secrets" do
      expect { StandardWebhooks::Webhook.new("") }.to raise_error(StandardWebhooks::EmptyWebhookSecretError)
      expect { StandardWebhooks::Webhook.new("whsec_") }.to raise_error(StandardWebhooks::EmptyWebhookSecretError)
    end
  end

  describe ".new_using_raw_bytes" do
    it "rejects empty webhook secrets" do
      expect { StandardWebhooks::Webhook.new("") }.to raise_error(StandardWebhooks::EmptyWebhookSecretError)
    end
  end

  it "missing id raises error" do
    testPayload = TestPayload.new
    testPayload.headers.delete("webhook-id")

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "missing timestamp raises error" do
    testPayload = TestPayload.new
    testPayload.headers.delete("webhook-timestamp")

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "missing signature raises error" do
    testPayload = TestPayload.new
    testPayload.headers.delete("webhook-signature")

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "invalid signature raises error" do
    testPayload = TestPayload.new
    testPayload.headers["webhook-signature"] = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLawdd"

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "valid signature is valid and returns valid json" do
    testPayload = TestPayload.new
    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.headers)
    expect(json["test"]).to eq(2432232314)
  end

  it "valid unbranded signature is valid and returns valid json" do
    testPayload = TestPayload.new
    unbrandedHeaders = {
      "webhook-id" => testPayload.headers["webhook-id"],
      "webhook-signature" => testPayload.headers["webhook-signature"],
      "webhook-timestamp" => testPayload.headers["webhook-timestamp"]
    }
    testPayload.headers = unbrandedHeaders

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.headers)
    expect(json["test"]).to eq(2432232314)
  end

  it "old timestamp raises error" do
    testPayload = TestPayload.new(Time.now.to_i - TOLERANCE - 1)

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "new timestamp raises error" do
    testPayload = TestPayload.new(Time.now.to_i + TOLERANCE + 1)

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "invalid timestamp raises error" do
    testPayload = TestPayload.new("teadwd")

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "multi sig pyload is valid" do
    testPayload = TestPayload.new
    sigs = [
      "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
      "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
      testPayload.headers["webhook-signature"], # valid signature
      "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc="
    ]
    testPayload.headers["webhook-signature"] = sigs.join(" ")

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.headers)
    expect(json["test"]).to eq(2432232314)
  end

  it "malformed signatures are skipped" do
    testPayload = TestPayload.new
    sigs = [
      "v1",
      "v1,not-base64!",
      testPayload.headers["webhook-signature"] # valid signature
    ]
    testPayload.headers["webhook-signature"] = sigs.join(" ")

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.headers)
    expect(json["test"]).to eq(2432232314)
  end

  it "valid signature with an unknown version raises error" do
    testPayload = TestPayload.new
    testPayload.headers["webhook-signature"] = "v2,#{testPayload.signature}"

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "signature with a version and no signature raises error" do
    testPayload = TestPayload.new
    testPayload.headers["webhook-signature"] = "v1"

    wh = StandardWebhooks::Webhook.new(testPayload.secret)

    expect {
      wh.verify(testPayload.payload, testPayload.headers)
    }.to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "signature verification works with and without prefix" do
    testPayload = TestPayload.new

    wh = StandardWebhooks::Webhook.new(testPayload.secret)
    json = wh.verify(testPayload.payload, testPayload.headers)
    expect(json["test"]).to eq(2432232314)

    wh = StandardWebhooks::Webhook.new("whsec_#{testPayload.secret}")
    json = wh.verify(testPayload.payload, testPayload.headers)
    expect(json["test"]).to eq(2432232314)
  end

  it "sign function works" do
    key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    msg_id = "msg_p5jXN8AQM9LWM0D4loKWxJek"
    timestamp = 1614265330
    payload = '{"test": 2432232314}'
    expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="

    wh = StandardWebhooks::Webhook.new(key)
    signature = wh.sign(msg_id, timestamp, payload)
    expect(signature).to eq(expected)
  end

  it "challenge response matches test vector" do
    wh = StandardWebhooks::Webhook.new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
    response = wh.challenge_response("0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=")
    expect(response).to eq("v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M=")
  end

  it "verify challenge response accepts test vector" do
    wh = StandardWebhooks::Webhook.new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
    challenge = "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM="
    header = "v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M="
    expect { wh.verify_challenge_response(challenge, header) }.not_to raise_error
  end

  it "verify challenge response rejects wrong challenge" do
    wh = StandardWebhooks::Webhook.new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
    challenge = "1njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM="
    header = "v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M="
    expect { wh.verify_challenge_response(challenge, header) }
      .to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "verify challenge response rejects lists" do
    wh = StandardWebhooks::Webhook.new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
    challenge = "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM="
    header = "v2,abc v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M="
    expect { wh.verify_challenge_response(challenge, header) }
      .to raise_error(StandardWebhooks::WebhookVerificationError)
  end

  it "challenge response depends on the secret" do
    wh = StandardWebhooks::Webhook.new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSx")
    response = wh.challenge_response("0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=")
    expect(response).not_to eq("v1,SA7z49ZgIXsSQs4atO5vKlidKLJEqzwAg3sh8yfob9M=")
  end
end
