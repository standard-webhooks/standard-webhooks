defmodule StandardWebhooks do
  @moduledoc """
  Documentation for `Standard Webhooks`
  """

  import Plug.Conn

  @secret_prefix "whsec_"
  @signature_identifier "v1"
  @tolerance 5 * 60
  @verification_key_label "wev-v1"

  @doc """
  Verify a Standard Webhook given a payload, Plug.Conn and secret
  """
  @spec verify(map(), Plug.Conn.t(), binary()) :: boolean()
  def verify(payload, conn, secret) do
    verify_signature(payload, conn, secret)
  end

  defp verify_signature(payload, conn, secret) do
    {id, timestamp, header_signatures} = get_req_headers(conn)

    signature = sign(id, String.to_integer(timestamp), payload, secret)

    valid_signatures?(header_signatures, signature)
  end

  defp get_req_headers(conn) do
    with [id] when is_binary(id) <- get_req_header(conn, "webhook-id"),
         [timestamp] when is_binary(timestamp) <- get_req_header(conn, "webhook-timestamp"),
         signatures when is_list(signatures) <- get_req_header(conn, "webhook-signature") do
      {id, timestamp, signatures}
    else
      _ ->
        raise ArgumentError, message: "Missing required headers"
    end
  end

  defp valid_signatures?(header_signatures, signature) do
    header_signatures
    |> Enum.flat_map(&String.split(&1, " "))
    |> Enum.any?(&Plug.Crypto.secure_compare(&1, signature))
  end

  def validate_timestamp(timestamp) do
    now = :os.system_time(:second)

    cond do
      is_integer(timestamp) and timestamp > now + @tolerance ->
        raise ArgumentError, message: "Message timestamp too new"

      is_integer(timestamp) and timestamp < now - @tolerance ->
        raise ArgumentError, message: "Message timestamp too old"

      true ->
        :ok
    end
  end

  @doc """
  Sign a Standard Webhook given an id, timestamp, payload and secret
  """
  @spec sign(
          id :: String.t(),
          timestamp :: integer(),
          payload :: map(),
          secret :: binary()
        ) ::
          String.t()
  def sign(id, _timestamp, _payload, _secret) when not is_binary(id) do
    raise ArgumentError, message: "Message id must be a string"
  end

  def sign(_id, timestamp, _payload, _secret) when not is_integer(timestamp) do
    raise ArgumentError, message: "Message timestamp must be an integer"
  end

  def sign(_id, _timestamp, payload, _secret) when not is_map(payload) do
    raise ArgumentError, message: "Message payload must be a map"
  end

  def sign(_id, _timestamp, _payload, secret) when not is_binary(secret) do
    raise ArgumentError, message: "Secret must be a string"
  end

  def sign(id, timestamp, payload, @secret_prefix <> secret) do
    sign_unprefixed(id, timestamp, payload, secret)
  end

  def sign(id, timestamp, payload, secret) do
    sign_unprefixed(id, timestamp, payload, secret)
  end

  defp sign_unprefixed(_id, _timestamp, _payload, "") do
    raise ArgumentError, message: "Secret must not be empty"
  end

  defp sign_unprefixed(_id, _timestamp, _payload, @secret_prefix <> _secret) do
    raise ArgumentError, message: "Secret has a duplicate \"#{@secret_prefix}\" prefix"
  end

  defp sign_unprefixed(id, timestamp, payload, secret) do
    sign_with_version(id, timestamp, payload, secret)
  end

  defp sign_with_version(id, timestamp, payload, secret) do
    validate_timestamp(timestamp)

    signature =
      to_sign(id, timestamp, payload)
      |> sign_and_encode(secret)

    "#{@signature_identifier},#{signature}"
  end

  @doc """
  Calculate the response to an endpoint verification challenge given a challenge and secret

  Takes the value of the `webhook-challenge` header and returns the value for the
  `webhook-challenge-response` header.
  """
  @spec endpoint_verification_response(challenge :: String.t(), secret :: binary()) :: String.t()
  def endpoint_verification_response(challenge, _secret) when not is_binary(challenge) do
    raise ArgumentError, message: "Challenge must be a string"
  end

  def endpoint_verification_response(_challenge, secret) when not is_binary(secret) do
    raise ArgumentError, message: "Secret must be a string"
  end

  def endpoint_verification_response(challenge, @secret_prefix <> secret) do
    endpoint_verification_response(challenge, secret)
  end

  def endpoint_verification_response(_challenge, secret) when secret == "" do
    raise ArgumentError, message: "Secret must not be empty"
  end

  def endpoint_verification_response(challenge, secret) do
    verification_key =
      :crypto.mac(:hmac, :sha256, Base.decode64!(secret), @verification_key_label)

    signature =
      :crypto.mac(:hmac, :sha256, verification_key, challenge)
      |> Base.encode64()

    "#{@signature_identifier},#{signature}"
  end

  @doc """
  Verify the response to an endpoint verification challenge given a challenge, response and secret

  Takes the challenge that was sent and the value of the `webhook-challenge-response` header.
  """
  @spec verify_endpoint_verification_response(
          challenge :: String.t(),
          header :: String.t(),
          secret :: binary()
        ) :: boolean()
  def verify_endpoint_verification_response(_challenge, header, _secret)
      when not is_binary(header) do
    raise ArgumentError, message: "Challenge response must be a string"
  end

  def verify_endpoint_verification_response(challenge, header, secret) do
    signature = endpoint_verification_response(challenge, secret)

    Plug.Crypto.secure_compare(header, signature)
  end

  defp to_sign(id, timestamp, payload) do
    encoded_payload = Jason.encode!(payload)

    "#{id}.#{timestamp}.#{encoded_payload}"
  end

  defp sign_and_encode(to_sign, secret) do
    :crypto.mac(:hmac, :sha256, Base.decode64!(secret), to_sign)
    |> Base.encode64()
    |> String.trim()
  end
end
