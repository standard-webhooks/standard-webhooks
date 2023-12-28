defmodule StandardWebhooksTest do
  use ExUnit.Case
  use Plug.Test

  alias StandardWebhooks, as: StandardWebhooks

  @id "msg_p5jXN8AQM9LWM0D4loKWxJek"
  @timestamp :os.system_time(:second)
  @tolerance 5 * 60
  @payload %{"event_type" => "ping"}
  @secret_prefix "whsec_"
  @secret "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
  @encoded_secret @secret_prefix <> Base.encode64(@secret)

  describe "sign/4" do
    test "raises error when message id is not a String" do
      assert_raise ArgumentError, "Message id must be a string", fn ->
        StandardWebhooks.sign(123, @timestamp, @payload, @secret)
      end
    end

    test "raises error when message timestamp is not an Integer" do
      assert_raise ArgumentError, "Message timestamp must be an integer", fn ->
        StandardWebhooks.sign(@id, to_string(@timestamp), @payload, @secret)
      end
    end

    test "raises error when message timestamp is too old" do
      assert_raise ArgumentError, "Message timestamp too old", fn ->
        timestamp = :os.system_time(:second) - @tolerance - 1
        StandardWebhooks.sign(@id, timestamp, @payload, @secret)
      end
    end

    test "raises error when message timestamp is too new" do
      assert_raise ArgumentError, "Message timestamp too new", fn ->
        timestamp = :os.system_time(:second) + @tolerance + 1
        StandardWebhooks.sign(@id, timestamp, @payload, @secret)
      end
    end

    test "raises error when message payload is not a Map" do
      assert_raise ArgumentError, "Message payload must be a map", fn ->
        StandardWebhooks.sign(@id, @timestamp, [], @secret)
      end
    end

    test "raises error when secret is not a String" do
      assert_raise ArgumentError, "Secret must be a string", fn ->
        StandardWebhooks.sign(@id, @timestamp, @payload, [])
      end
    end

    test "returns valid signature when unencoded secret" do
      [signature_identifier, signature] =
        StandardWebhooks.sign(@id, @timestamp, @payload, @secret) |> String.split(",")

      {:ok, decoded_signature} = Base.decode64(signature)

      assert "v1" == signature_identifier
      assert is_binary(decoded_signature)
    end

    test "returns valid signature when encoded secret" do
      [signature_identifier, signature] =
        StandardWebhooks.sign(@id, @timestamp, @payload, @encoded_secret) |> String.split(",")

      {:ok, decoded_signature} = Base.decode64(signature)

      assert "v1" == signature_identifier
      assert is_binary(decoded_signature)
    end
  end

  describe "verify/2" do
    setup do
      signature = StandardWebhooks.sign(@id, @timestamp, @payload, @secret)

      {:ok, signature: signature}
    end

    test "return true when valid encoded_secret and signature", %{signature: signature} do
      conn = setup_webhook(signature)

      assert StandardWebhooks.verify(conn, @payload, @encoded_secret)
    end

    test "return true when valid secret and signature", %{signature: signature} do
      conn = setup_webhook(signature)

      assert StandardWebhooks.verify(conn, @payload, @secret)
    end

    test "return false when valid secret and invalid signature" do
      conn = setup_webhook("invalid signature")

      assert false == StandardWebhooks.verify(conn, @payload, @secret)
    end

    test "raises error when missing webhook header", %{signature: signature} do
      connection =
        conn(:post, "/_incoming", @payload)
        |> put_req_header("webhook-timestamp", to_string(@timestamp))
        |> put_req_header("webhook-signature", signature)

      assert_raise ArgumentError, "Missing required headers", fn ->
        StandardWebhooks.verify(connection, @payload, @secret)
      end
    end
  end

  defp setup_webhook(signature) do
    conn(:post, "/_incoming", @payload)
    |> put_req_header("webhook-id", @id)
    |> put_req_header("webhook-timestamp", to_string(@timestamp))
    |> put_req_header("webhook-signature", signature)
  end
end
