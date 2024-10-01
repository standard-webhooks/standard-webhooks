# frozen_string_literal: true

require "json"
require "openssl"
require "base64"
require "uri"

module StandardWebhooks
  class Webhook

    def self.new_using_raw_bytes(secret)
      self.new(secret.pack("C*").force_encoding("UTF-8"))
    end

    def initialize(secret)
      if secret.start_with?(SECRET_PREFIX)
        secret = secret[SECRET_PREFIX.length..-1]
      end

      @secret = Base64.decode64(secret)
    end

    def verify(payload, headers)
      msg_id = headers["webhook-id"]
      msg_signature = headers["webhook-signature"]
      msg_timestamp = headers["webhook-timestamp"]

      if !msg_signature || !msg_id || !msg_timestamp
        raise WebhookVerificationError, "Missing required headers"
      end

      verify_timestamp(msg_timestamp)

      _, signature = sign(msg_id, msg_timestamp, payload).split(",", 2)

      passed_signatures = msg_signature.split(" ")

      passed_signatures.each do |versioned_signature|
        version, expected_signature = versioned_signature.split(",", 2)

        if version != "v1"
          next
        end

        if ::StandardWebhooks::secure_compare(signature, expected_signature)
          return JSON.parse(payload, symbolize_names: true)
        end
      end

      raise WebhookVerificationError, "No matching signature found"
    end

    def sign(msg_id, timestamp, payload)
      begin
        now = Integer(timestamp)
      rescue
        raise WebhookSigningError, "Invalid timestamp"
      end

      to_sign = "#{msg_id}.#{timestamp}.#{payload}"
      signature = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), @secret, to_sign)).strip

      return "v1,#{signature}"
    end

    private

    SECRET_PREFIX = "whsec_"
    TOLERANCE = 5 * 60

    def verify_timestamp(timestamp_header)
      begin
        now = Integer(Time.now)
        timestamp = Integer(timestamp_header)
      rescue
        raise WebhookVerificationError, "Invalid Signature Headers"
      end

      if timestamp < (now - TOLERANCE)
        raise WebhookVerificationError, "Message timestamp too old"
      end

      if timestamp > (now + TOLERANCE)
        raise WebhookVerificationError, "Message timestamp too new"
      end
    end
  end
end
