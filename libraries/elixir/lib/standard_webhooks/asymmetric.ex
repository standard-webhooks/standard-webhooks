defmodule StandardWebhooks.Asymmetric do
  @moduledoc """
  Verify Standard Webhooks signed with the asymmetric `v2a` signature scheme
  (ed25519 over the SHA-256 hash of `endpoint_id.msg_id.timestamp.payload`).

  This module only verifies: producers are expected to hold the private keys in a KMS or an HSM.

      webhook = StandardWebhooks.Asymmetric.new(endpoint_id, [public_key])
      StandardWebhooks.Asymmetric.verify(webhook_payload, plug_conn, webhook)
  """

  @public_key_prefix "whpk_"
  @signature_identifier "v2a"
  @verification_key_label "wev-v1"

  @enforce_keys [:public_keys, :endpoint_id]
  defstruct [:public_keys, :endpoint_id]

  @type t :: %__MODULE__{public_keys: [binary()], endpoint_id: String.t()}

  @doc """
  Create a verifier given an endpoint ID and a list of trusted public keys

  `endpoint_id` is the endpoint ID the producer shared with you together with the public keys.
  Never take it from the request.

  `public_keys` is a non-empty list of `whpk_` prefixed public keys. A webhook is accepted if it's
  signed by any of them, so keys can be rotated by adding the new key to the list. The order only
  matters for endpoint verification, which uses the first key: put the newest key first.
  """
  @spec new(endpoint_id :: String.t(), public_keys :: [String.t()]) :: t()
  def new(_endpoint_id, []) do
    raise ArgumentError, message: "Public keys must not be empty"
  end

  def new(_endpoint_id, public_keys) when not is_list(public_keys) do
    raise ArgumentError, message: "Public keys must be a list"
  end

  def new(endpoint_id, _public_keys) when not is_binary(endpoint_id) do
    raise ArgumentError, message: "Endpoint ID must be a string"
  end

  def new("", _public_keys) do
    raise ArgumentError, message: "Endpoint ID must not be empty"
  end

  def new(endpoint_id, public_keys) do
    if String.contains?(endpoint_id, ".") do
      raise ArgumentError, message: "Endpoint ID must not contain a \".\""
    end

    %__MODULE__{
      public_keys: Enum.map(public_keys, &decode_public_key/1),
      endpoint_id: endpoint_id
    }
  end

  defp decode_public_key(@public_key_prefix <> public_key) do
    case Base.decode64(public_key) do
      {:ok, <<_::binary-size(32)>> = raw_public_key} ->
        raw_public_key

      _ ->
        raise ArgumentError, message: "Public key must be a base64 encoded 32 byte key"
    end
  end

  defp decode_public_key(_public_key) do
    raise ArgumentError, message: "Public key must start with \"#{@public_key_prefix}\""
  end

  @doc """
  Verify a Standard Webhook given a payload, Plug.Conn and verifier created with `new/2`

  The payload must be the raw request body, exactly as received, either as bytes (a binary) or
  as a string (a UTF-8 binary). It's verified byte for byte, so don't pass a re-encoded version
  of the parsed body: even a minor difference in the serialization (e.g. whitespace or key
  order) will cause verification to fail.
  """
  @spec verify(binary() | String.t(), Plug.Conn.t(), t()) :: boolean()
  def verify(payload, _conn, _webhook) when not is_binary(payload) do
    raise ArgumentError, message: "Message payload must be a binary or a string"
  end

  def verify(payload, conn, %__MODULE__{} = webhook) do
    {id, timestamp, header_signatures} = StandardWebhooks.get_req_headers(conn)

    timestamp = String.to_integer(timestamp)
    StandardWebhooks.validate_timestamp(timestamp)

    content = "#{webhook.endpoint_id}.#{id}.#{timestamp}." <> payload
    digest = :crypto.hash(:sha256, content)

    header_signatures
    |> Enum.flat_map(&String.split(&1, " "))
    |> Enum.any?(&valid_signature?(&1, digest, webhook.public_keys))
  end

  defp valid_signature?(@signature_identifier <> "," <> signature, digest, public_keys) do
    case Base.decode64(signature) do
      {:ok, <<_::binary-size(64)>> = decoded_signature} ->
        Enum.any?(public_keys, &ed25519_verify?(digest, decoded_signature, &1))

      _ ->
        false
    end
  end

  defp valid_signature?(_signature, _digest, _public_keys), do: false

  defp ed25519_verify?(digest, signature, public_key) do
    :crypto.verify(:eddsa, :none, digest, signature, [public_key, :ed25519])
  end

  @doc """
  Calculate the response to an endpoint verification challenge given a challenge and verifier

  Takes the value of the `webhook-challenge` header and returns the value for the
  `webhook-challenge-response` header. Uses the first (newest) public key.
  """
  @spec endpoint_verification_response(challenge :: String.t(), webhook :: t()) :: String.t()
  def endpoint_verification_response(challenge, _webhook) when not is_binary(challenge) do
    raise ArgumentError, message: "Challenge must be a string"
  end

  def endpoint_verification_response(challenge, %__MODULE__{} = webhook) do
    [public_key | _] = webhook.public_keys

    calculate_endpoint_verification_response(challenge, public_key, webhook.endpoint_id)
  end

  @doc """
  Verify the response to an endpoint verification challenge given a challenge, header and verifier

  Takes the challenge that was sent and the value of the `webhook-challenge-response` header.
  Returns true if the response was calculated with any of the public keys.
  """
  @spec verify_endpoint_verification_response(
          challenge :: String.t(),
          header :: String.t(),
          webhook :: t()
        ) :: boolean()
  def verify_endpoint_verification_response(_challenge, header, _webhook)
      when not is_binary(header) do
    raise ArgumentError, message: "Challenge response must be a string"
  end

  def verify_endpoint_verification_response(challenge, _header, _webhook)
      when not is_binary(challenge) do
    raise ArgumentError, message: "Challenge must be a string"
  end

  def verify_endpoint_verification_response(challenge, header, %__MODULE__{} = webhook) do
    Enum.any?(webhook.public_keys, fn public_key ->
      signature =
        calculate_endpoint_verification_response(challenge, public_key, webhook.endpoint_id)

      Plug.Crypto.secure_compare(header, signature)
    end)
  end

  defp calculate_endpoint_verification_response(challenge, public_key, endpoint_id) do
    verification_key =
      :crypto.mac(:hmac, :sha256, public_key <> "." <> endpoint_id, @verification_key_label)

    signature =
      :crypto.mac(:hmac, :sha256, verification_key, challenge)
      |> Base.encode64()

    "#{@signature_identifier},#{signature}"
  end
end
