defmodule StandardWebhooks.AsymmetricTest do
  use ExUnit.Case
  use Plug.Test

  alias StandardWebhooks.Asymmetric

  @id "msg_p5jXN8AQM9LWM0D4loKWxJek"
  @tolerance 5 * 60
  @payload ~s({"event_type":"ping"})
  @secret_key "whsk_4uKPjji/dhB8w6GW3YYDnIMYvXcdHrvH6lidTr4Z+EY="
  @public_key "whpk_uWKK13PfwqyOgrqT0OrWKcS2uVD7e89+oUKnkoPjx7w="
  @endpoint_id "ep_2fVZdC8Kx9TR4ZoCqHWt3NnLgRb"
  @challenge "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM="
  @challenge_response "v2a,t0RDFhzk7OtVzgvMsjuXnodSWuby2BVX+zPqw2/ksUk="
  @spec_signature "v2a,kG9XaxZjAEpKB8KeQQb5G1Xp73YH5Rf5gxoWe7cg1kYMiyspdtZXe9w+dAwKeOurAwxfqmlOG/QR4m9s37DzAg=="
  @other_signatures [
    "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    "v2a,not-base64!",
    "v2a,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    "v2a"
  ]

  describe "new/2" do
    test "returns a verifier when valid public keys and endpoint id" do
      assert %Asymmetric{endpoint_id: @endpoint_id} = Asymmetric.new(@endpoint_id, [@public_key])
    end

    test "raises error when public keys are empty" do
      assert_raise ArgumentError, "Public keys must not be empty", fn ->
        Asymmetric.new(@endpoint_id, [])
      end
    end

    test "raises error when public key is missing the prefix" do
      assert_raise ArgumentError, ~s(Public key must start with "whpk_"), fn ->
        Asymmetric.new(@endpoint_id, [String.replace_prefix(@public_key, "whpk_", "")])
      end

      assert_raise ArgumentError, ~s(Public key must start with "whpk_"), fn ->
        Asymmetric.new(@endpoint_id, [@secret_key])
      end
    end

    test "raises error when public key has the wrong length" do
      for raw_public_key <- [:binary.copy("a", 31), :binary.copy("a", 33), ""] do
        assert_raise ArgumentError, fn ->
          Asymmetric.new(@endpoint_id, ["whpk_" <> Base.encode64(raw_public_key)])
        end
      end
    end

    test "raises error when public key is not valid base64" do
      assert_raise ArgumentError, fn ->
        Asymmetric.new(@endpoint_id, ["whpk_not-base64!"])
      end
    end

    test "raises error when endpoint id is empty" do
      assert_raise ArgumentError, "Endpoint ID must not be empty", fn ->
        Asymmetric.new("", [@public_key])
      end
    end

    test "raises error when endpoint id contains a dot" do
      assert_raise ArgumentError, ~s(Endpoint ID must not contain a "."), fn ->
        Asymmetric.new("ep_1.2", [@public_key])
      end
    end
  end

  describe "test vectors" do
    test "the secret key matches the public key" do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, spec_seed())

      assert @public_key == "whpk_" <> Base.encode64(public_key)
    end

    test "the signature matches the spec" do
      # The vector's timestamp is outside of the tolerance, so check it against the primitive
      prefix = "#{@endpoint_id}.msg_2KWPBgLlAfxdpx2AI54pPJ85f4W.1674087231."
      payload = ~s({"type":"contact.created","timestamp":"2022-11-03T20:26:10.344522Z",)
      data = ~s("data":{"id":"1f81eb52-5198-4599-803e-771906343485"}})

      digest = :crypto.hash(:sha256, prefix <> payload <> data)
      assert "YXCi5iN+rjB+iEb6bvg1XbWbVBL+r2S+as3k3n1Ih/A=" == Base.encode64(digest)

      "v2a," <> signature = @spec_signature
      signature = Base.decode64!(signature)
      "whpk_" <> public_key = @public_key
      public_key = Base.decode64!(public_key)

      assert :crypto.verify(:eddsa, :none, digest, signature, [public_key, :ed25519])

      assert signature == :crypto.sign(:eddsa, :none, digest, [spec_seed(), :ed25519])
    end
  end

  describe "verify/3" do
    setup do
      {:ok, webhook: Asymmetric.new(@endpoint_id, [@public_key])}
    end

    test "return true when valid signature", %{webhook: webhook} do
      conn = signed_webhook(spec_seed(), @endpoint_id)

      assert Asymmetric.verify(@payload, conn, webhook)
    end

    test "return true when valid signature alongside other signatures", %{webhook: webhook} do
      timestamp = now()

      signature = sign(spec_seed(), @endpoint_id, timestamp)
      signatures = Enum.join(@other_signatures ++ [signature], " ")
      conn = setup_webhook(signatures, timestamp)

      assert Asymmetric.verify(@payload, conn, webhook)
    end

    test "return true when signed by the second public key" do
      {public_key, seed} = :crypto.generate_key(:eddsa, :ed25519)
      webhook = Asymmetric.new(@endpoint_id, [@public_key, "whpk_" <> Base.encode64(public_key)])
      conn = signed_webhook(seed, @endpoint_id)

      assert Asymmetric.verify(@payload, conn, webhook)
    end

    test "return false when signed by an untrusted key", %{webhook: webhook} do
      {_public_key, seed} = :crypto.generate_key(:eddsa, :ed25519)
      conn = signed_webhook(seed, @endpoint_id)

      refute Asymmetric.verify(@payload, conn, webhook)
    end

    test "return false when signed for another endpoint", %{webhook: webhook} do
      conn = signed_webhook(spec_seed(), "ep_other")

      refute Asymmetric.verify(@payload, conn, webhook)
    end

    test "return false when payload is tampered", %{webhook: webhook} do
      conn = signed_webhook(spec_seed(), @endpoint_id)

      refute Asymmetric.verify(~s({"event_type":"pong"}), conn, webhook)
    end

    test "return false when the payload is serialized differently", %{webhook: webhook} do
      conn = signed_webhook(spec_seed(), @endpoint_id)

      refute Asymmetric.verify(~s({"event_type": "ping"}), conn, webhook)
    end

    test "return true for a binary (non UTF-8) payload", %{webhook: webhook} do
      payload = <<0xFF, 0x00, 0xFE, 0x80>>
      timestamp = now()
      conn = setup_webhook(sign(spec_seed(), @endpoint_id, timestamp, payload), timestamp)

      assert Asymmetric.verify(payload, conn, webhook)
      refute Asymmetric.verify(<<0xFF, 0x00, 0xFE, 0x81>>, conn, webhook)
    end

    test "raises error when the payload is a map", %{webhook: webhook} do
      conn = signed_webhook(spec_seed(), @endpoint_id)

      assert_raise ArgumentError, "Message payload must be a binary or a string", fn ->
        Asymmetric.verify(%{"event_type" => "ping"}, conn, webhook)
      end
    end

    test "return false when valid signature with another version", %{webhook: webhook} do
      timestamp = now()
      signature = sign(spec_seed(), @endpoint_id, timestamp)
      conn = setup_webhook(String.replace(signature, "v2a,", "v1a,", global: false), timestamp)

      refute Asymmetric.verify(@payload, conn, webhook)
    end

    test "raises error when message timestamp is too old", %{webhook: webhook} do
      timestamp = now() - @tolerance - 1
      conn = setup_webhook(sign(spec_seed(), @endpoint_id, timestamp), timestamp)

      assert_raise ArgumentError, "Message timestamp too old", fn ->
        Asymmetric.verify(@payload, conn, webhook)
      end
    end

    test "raises error when message timestamp is too new", %{webhook: webhook} do
      timestamp = now() + @tolerance + 1
      conn = setup_webhook(sign(spec_seed(), @endpoint_id, timestamp), timestamp)

      assert_raise ArgumentError, "Message timestamp too new", fn ->
        Asymmetric.verify(@payload, conn, webhook)
      end
    end

    test "raises error when missing webhook id header", %{webhook: webhook} do
      timestamp = now()

      connection =
        conn(:post, "/_incoming", @payload)
        |> put_req_header("webhook-timestamp", to_string(timestamp))
        |> put_req_header("webhook-signature", sign(spec_seed(), @endpoint_id, timestamp))

      assert_raise ArgumentError, "Missing required headers", fn ->
        Asymmetric.verify(@payload, connection, webhook)
      end
    end

    test "raises error when missing webhook timestamp header", %{webhook: webhook} do
      connection =
        conn(:post, "/_incoming", @payload)
        |> put_req_header("webhook-id", @id)
        |> put_req_header("webhook-signature", sign(spec_seed(), @endpoint_id, now()))

      assert_raise ArgumentError, "Missing required headers", fn ->
        Asymmetric.verify(@payload, connection, webhook)
      end
    end

    test "return false when missing webhook signature header", %{webhook: webhook} do
      connection =
        conn(:post, "/_incoming", @payload)
        |> put_req_header("webhook-id", @id)
        |> put_req_header("webhook-timestamp", to_string(now()))

      refute Asymmetric.verify(@payload, connection, webhook)
    end
  end

  describe "endpoint_verification_response/2" do
    test "returns valid response" do
      webhook = Asymmetric.new(@endpoint_id, [@public_key])

      assert @challenge_response == Asymmetric.endpoint_verification_response(@challenge, webhook)
    end

    test "uses the first public key" do
      other_key = random_public_key()

      webhook = Asymmetric.new(@endpoint_id, [@public_key, other_key])
      assert @challenge_response == Asymmetric.endpoint_verification_response(@challenge, webhook)

      webhook = Asymmetric.new(@endpoint_id, [other_key, @public_key])
      refute @challenge_response == Asymmetric.endpoint_verification_response(@challenge, webhook)
    end
  end

  describe "verify_endpoint_verification_response/3" do
    setup do
      {:ok, webhook: Asymmetric.new(@endpoint_id, [random_public_key(), @public_key])}
    end

    test "returns true when valid response for any of the public keys", %{webhook: webhook} do
      assert Asymmetric.verify_endpoint_verification_response(
               @challenge,
               @challenge_response,
               webhook
             )
    end

    test "returns false when wrong response", %{webhook: webhook} do
      refute Asymmetric.verify_endpoint_verification_response(@challenge, "v2a,abc", webhook)

      refute Asymmetric.verify_endpoint_verification_response(
               @challenge,
               String.replace(@challenge_response, "v2a,", "v1,"),
               webhook
             )
    end

    test "returns false when wrong challenge", %{webhook: webhook} do
      refute Asymmetric.verify_endpoint_verification_response(
               "wrong-challenge",
               @challenge_response,
               webhook
             )
    end
  end

  defp now, do: :os.system_time(:second)

  defp spec_seed do
    "whsk_" <> seed = @secret_key
    Base.decode64!(seed)
  end

  defp random_public_key do
    {public_key, _seed} = :crypto.generate_key(:eddsa, :ed25519)
    "whpk_" <> Base.encode64(public_key)
  end

  defp sign(seed, endpoint_id, timestamp, payload \\ @payload) do
    content = "#{endpoint_id}.#{@id}.#{timestamp}." <> payload
    digest = :crypto.hash(:sha256, content)
    signature = :crypto.sign(:eddsa, :none, digest, [seed, :ed25519])

    "v2a," <> Base.encode64(signature)
  end

  defp signed_webhook(seed, endpoint_id) do
    timestamp = now()

    setup_webhook(sign(seed, endpoint_id, timestamp), timestamp)
  end

  defp setup_webhook(signature, timestamp) do
    conn(:post, "/_incoming", @payload)
    |> put_req_header("webhook-id", @id)
    |> put_req_header("webhook-timestamp", to_string(timestamp))
    |> put_req_header("webhook-signature", signature)
  end
end
