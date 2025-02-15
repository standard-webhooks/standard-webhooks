defmodule StandardWebhooks do
  @moduledoc """
  Documentation for `Standard Webhooks`
  """

  import Plug.Conn

  @secret_prefix "whsec_"
  @signature_identifier "v1"
  @tolerance 5 * 60

  @doc """
  Verify a Standard Webhook given a payload, Plug.Conn and secret
  """
  @spec verify(map(), Plug.Conn.t(), binary()) :: boolean()
  def verify(payload, conn, @secret_prefix <> encoded_secret) do
    verify_signature(payload, conn, Base.decode64!(encoded_secret))
  end

  def verify(payload, conn, secret) do
    verify_signature(payload, conn, secret)
  end

  defp verify_signature(payload, conn, secret) do
    {id, timestamp, header_signatures} = get_req_headers(conn)

    signature =
      sign(id, String.to_integer(timestamp), payload, secret)
      |> split_signature_from_identifier()

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

  defp valid_signatures?([], _signature), do: false

  defp valid_signatures?(signatures, signature) when signature >= 1 do
    signatures
    |> Enum.map(&split_signature_from_identifier/1)
    |> Enum.any?(&Plug.Crypto.secure_compare(&1, signature))
  end

  defp split_signature_from_identifier(signature) do
    signature
    |> String.split(",")
    |> List.last()
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
    decoded_secret = Base.decode64!(secret)

    sign_with_version(id, timestamp, payload, decoded_secret)
  end

  def sign(id, timestamp, payload, secret) do
    sign_with_version(id, timestamp, payload, secret)
  end

  defp sign_with_version(id, timestamp, payload, secret) do
    validate_timestamp(timestamp)

    signature =
      to_sign(id, timestamp, payload)
      |> sign_and_encode(secret)

    "#{@signature_identifier},#{signature}"
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
