# frozen_string_literal: true

require "json"
require "openssl"
require "base64"

module StandardWebhooks
  # Verifies webhooks signed with the asymmetric `v2a` signature scheme
  # (ed25519 over the SHA-256 hash of `endpoint_id.msg_id.timestamp.payload`).
  #
  # This class only verifies: producers are expected to hold the private keys in
  # a KMS or an HSM.
  class WebhookAsymmetric
    include TimestampVerification

    # endpoint_id: the endpoint ID the producer shared with you together with the
    #   public keys. Never take it from the request.
    # public_keys: a non-empty list of trusted `whpk_` prefixed public keys.
    #   A webhook is accepted if it's signed by any of them, so keys can be rotated
    #   by adding the new key to the list. The order only matters for endpoint
    #   verification, which uses the first key: put the newest key first.
    def initialize(endpoint_id, public_keys)
      if !public_keys.is_a?(Array) || public_keys.empty?
        raise EmptyWebhookSecretError, "Public keys must not be empty"
      end

      @raw_public_keys = public_keys.map { |key| decode_public_key(key) }
      @public_keys = @raw_public_keys.map do |raw_key|
        OpenSSL::PKey.read(ED25519_SPKI_PREFIX + raw_key)
      end

      if !endpoint_id.is_a?(String) || endpoint_id.empty?
        raise EmptyWebhookSecretError, "Endpoint ID must not be blank"
      end

      if endpoint_id.include?(".")
        raise EmptyWebhookSecretError, "Endpoint ID must not contain a '.'"
      end

      @endpoint_id = endpoint_id
    end

    def verify(payload, headers)
      msg_id = headers["webhook-id"]
      msg_signature = headers["webhook-signature"]
      msg_timestamp = headers["webhook-timestamp"]

      if !msg_signature || !msg_id || !msg_timestamp
        raise WebhookVerificationError, "Missing required headers"
      end

      timestamp = verify_timestamp(msg_timestamp)

      content = "#{@endpoint_id}.#{msg_id}.#{timestamp}.".b + payload.to_s.b
      digest = OpenSSL::Digest.new("sha256").digest(content)

      passed_signatures = msg_signature.split(" ")
      matched = passed_signatures.any? do |versioned_signature|
        version, signature = versioned_signature.split(",", 2)
        next false unless version == SIGNATURE_IDENTIFIER && signature

        begin
          signature = Base64.strict_decode64(signature)
        rescue ArgumentError
          next false
        end
        next false unless signature.bytesize == SIGNATURE_LENGTH

        @public_keys.any? { |public_key| ed25519_verify(public_key, signature, digest) }
      end

      unless matched
        raise WebhookVerificationError, "No matching signature found"
      end

      JSON.parse(payload)
    end

    # Calculate the response to an endpoint verification challenge. Takes the value of the
    # `webhook-challenge` request header and returns the value for the
    # `webhook-challenge-response` response header. Uses the first (newest) public key.
    def endpoint_verification_response(challenge)
      calculate_endpoint_verification_response(@raw_public_keys.first, challenge)
    end

    # Verify the response to an endpoint verification challenge. Takes the challenge sent in
    # the `webhook-challenge` request header and the value of the `webhook-challenge-response`
    # response header. Succeeds if the response was calculated with any of the public keys.
    # Raises WebhookVerificationError if no matching signature is found.
    def verify_endpoint_verification_response(challenge, header)
      matched = header.is_a?(String) && @raw_public_keys.any? { |raw_key|
        expected = calculate_endpoint_verification_response(raw_key, challenge)
        ::StandardWebhooks.secure_compare(header, expected)
      }

      unless matched
        raise WebhookVerificationError, "No matching signature found"
      end
    end

    PUBLIC_KEY_PREFIX = "whpk_"
    SIGNATURE_IDENTIFIER = "v2a"
    PUBLIC_KEY_LENGTH = 32
    SIGNATURE_LENGTH = 64
    # DER encoded SubjectPublicKeyInfo header for a raw ed25519 public key.
    ED25519_SPKI_PREFIX = ["302a300506032b6570032100"].pack("H*").freeze
    private_constant :PUBLIC_KEY_PREFIX, :SIGNATURE_IDENTIFIER, :PUBLIC_KEY_LENGTH,
      :SIGNATURE_LENGTH, :ED25519_SPKI_PREFIX

    private

    def decode_public_key(key)
      unless key.is_a?(String) && key.start_with?(PUBLIC_KEY_PREFIX)
        raise EmptyWebhookSecretError, "Public key must start with \"#{PUBLIC_KEY_PREFIX}\""
      end

      begin
        raw_key = Base64.strict_decode64(key[PUBLIC_KEY_PREFIX.length..-1])
      rescue ArgumentError
        raise EmptyWebhookSecretError, "Public key must be valid base64"
      end

      unless raw_key.bytesize == PUBLIC_KEY_LENGTH
        raise EmptyWebhookSecretError, "Public key must be #{PUBLIC_KEY_LENGTH} bytes"
      end

      raw_key
    end

    def ed25519_verify(public_key, signature, digest)
      public_key.verify(nil, signature, digest)
    rescue OpenSSL::PKey::PKeyError
      false
    end

    def calculate_endpoint_verification_response(raw_key, challenge)
      endpoint_key = raw_key + ".".b + @endpoint_id.b
      verification_key = OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), endpoint_key, "wev-v1")
      digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), verification_key, challenge)
      signature = Base64.strict_encode64(digest)

      "#{SIGNATURE_IDENTIFIER},#{signature}"
    end
  end
end
