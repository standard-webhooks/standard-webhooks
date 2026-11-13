package com.standardwebhooks;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;

import com.standardwebhooks.exceptions.EmptyWebhookSecretException;
import com.standardwebhooks.exceptions.WebhookSigningException;
import com.standardwebhooks.exceptions.WebhookVerificationException;

/**
 * Unit tests for WebhookAsymmetricBase core logic, using the test vectors from the spec.
 */
public class WebhookAsymmetricTest {
	// Test-only secret key (ed25519 seed) from the spec. Never use it for anything real.
	private static final String SECRET_KEY = "whsk_4uKPjji/dhB8w6GW3YYDnIMYvXcdHrvH6lidTr4Z+EY=";
	private static final String PUBLIC_KEY = "whpk_uWKK13PfwqyOgrqT0OrWKcS2uVD7e89+oUKnkoPjx7w=";
	private static final String ENDPOINT_ID = "ep_2fVZdC8Kx9TR4ZoCqHWt3NnLgRb";
	private static final String MSG_ID = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W";
	private static final long TIMESTAMP = 1674087231L;
	private static final String PAYLOAD = "{\"type\":\"contact.created\",\"timestamp\":\"2022-11-03T20:26:10.344522Z\",\"data\":{\"id\":\"1f81eb52-5198-4599-803e-771906343485\"}}";
	private static final String DIGEST = "YXCi5iN+rjB+iEb6bvg1XbWbVBL+r2S+as3k3n1Ih/A=";
	private static final String SIGNATURE = "v2a,kG9XaxZjAEpKB8KeQQb5G1Xp73YH5Rf5gxoWe7cg1kYMiyspdtZXe9w+dAwKeOurAwxfqmlOG/QR4m9s37DzAg==";
	private static final String CHALLENGE = "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=";
	private static final String CHALLENGE_RESPONSE = "v2a,t0RDFhzk7OtVzgvMsjuXnodSWuby2BVX+zPqw2/ksUk=";

	// A second, unrelated key pair, for key rotation tests
	private static final Ed25519PrivateKeyParameters OTHER_SECRET_KEY = new Ed25519PrivateKeyParameters(new byte[32], 0);
	private static final String OTHER_PUBLIC_KEY = WebhookAsymmetricBase.PUBLIC_KEY_PREFIX
		+ Base64.getEncoder().encodeToString(OTHER_SECRET_KEY.generatePublicKey().getEncoded());

	private static Ed25519PrivateKeyParameters secretKey() {
		byte[] seed = Base64.getDecoder().decode(SECRET_KEY.substring("whsk_".length()));
		return new Ed25519PrivateKeyParameters(seed, 0);
	}

	private static String sign(final Ed25519PrivateKeyParameters key, final String endpointId, final String msgId,
			final long timestamp, final String payload) throws Exception {
		String content = String.format("%s.%s.%s.%s", endpointId, msgId, timestamp, payload);
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8));
		Ed25519Signer signer = new Ed25519Signer();
		signer.init(true, key);
		signer.update(digest, 0, digest.length);
		return "v2a," + Base64.getEncoder().encodeToString(signer.generateSignature());
	}

	private static long now() {
		return System.currentTimeMillis() / 1000;
	}

	private static Map<String, List<String>> headers(final String msgId, final long timestamp, final String signature) {
		Map<String, List<String>> headers = new HashMap<>();
		headers.put("webhook-id", new ArrayList<>(Arrays.asList(msgId)));
		headers.put("webhook-timestamp", new ArrayList<>(Arrays.asList(String.valueOf(timestamp))));
		headers.put("webhook-signature", new ArrayList<>(Arrays.asList(signature)));
		return headers;
	}

	private static WebhookAsymmetric webhook(final String... publicKeys) throws EmptyWebhookSecretException {
		return new WebhookAsymmetric(ENDPOINT_ID, Arrays.asList(publicKeys));
	}

	private static ThrowingRunnable verify(final WebhookAsymmetric webhook, final String payload,
			final Map<String, List<String>> headers) {
		return new ThrowingRunnable() {
			@Override
			public void run() throws WebhookVerificationException {
				webhook.verify(payload, headers);
			}
		};
	}

	private static ThrowingRunnable construct(final String endpointId, final List<String> publicKeys) {
		return new ThrowingRunnable() {
			@Override
			public void run() throws EmptyWebhookSecretException {
				new WebhookAsymmetric(endpointId, publicKeys);
			}
		};
	}

	@Test
	public void verifySpecVector() throws Exception {
		String content = String.format("%s.%s.%s.%s", ENDPOINT_ID, MSG_ID, TIMESTAMP, PAYLOAD);
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8));
		assertEquals(DIGEST, Base64.getEncoder().encodeToString(digest));

		Ed25519PublicKeyParameters publicKey = secretKey().generatePublicKey();
		assertEquals(PUBLIC_KEY, "whpk_" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		assertEquals(SIGNATURE, sign(secretKey(), ENDPOINT_ID, MSG_ID, TIMESTAMP, PAYLOAD));

		// The vector's timestamp is outside the tolerance, so skip the timestamp check
		webhook(PUBLIC_KEY).verifySignature(MSG_ID, TIMESTAMP, PAYLOAD, SIGNATURE);
	}

	@Test
	public void verifySpecVectorTimestampTooOld() throws Exception {
		assertThrows(WebhookVerificationException.class,
			verify(webhook(PUBLIC_KEY), PAYLOAD, headers(MSG_ID, TIMESTAMP, SIGNATURE)));
	}

	@Test
	public void verifyValidSignature() throws Exception {
		long timestamp = now();
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		webhook(PUBLIC_KEY).verify(PAYLOAD, headers(MSG_ID, timestamp, signature));
	}

	@Test
	public void verifyCaseInsensitiveHeaders() throws Exception {
		long timestamp = now();
		Map<String, List<String>> headers = new HashMap<>();
		headers.put("Webhook-Id", Collections.singletonList(MSG_ID));
		headers.put("WEBHOOK-TIMESTAMP", Collections.singletonList(String.valueOf(timestamp)));
		headers.put("webhook-SIGNATURE", Collections.singletonList(sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD)));
		webhook(PUBLIC_KEY).verify(PAYLOAD, headers);
	}

	@Test
	public void verifyMultipleSignaturesIsValid() throws Exception {
		long timestamp = now();
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		String header = String.join(" ",
			"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
			"v2a,invalid",
			"v1a,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
			signature);
		webhook(PUBLIC_KEY).verify(PAYLOAD, headers(MSG_ID, timestamp, header));
	}

	@Test
	public void verifySignatureBySecondKeyIsValid() throws Exception {
		long timestamp = now();
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		webhook(OTHER_PUBLIC_KEY, PUBLIC_KEY).verify(PAYLOAD, headers(MSG_ID, timestamp, signature));
	}

	@Test
	public void verifySignatureByUnknownKeyThrowsException() throws Exception {
		long timestamp = now();
		String signature = sign(OTHER_SECRET_KEY, ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		assertThrows(WebhookVerificationException.class,
			verify(webhook(PUBLIC_KEY), PAYLOAD, headers(MSG_ID, timestamp, signature)));
	}

	@Test
	public void verifyWrongEndpointIdThrowsException() throws Exception {
		long timestamp = now();
		String signature = sign(secretKey(), "ep_other", MSG_ID, timestamp, PAYLOAD);
		assertThrows(WebhookVerificationException.class,
			verify(webhook(PUBLIC_KEY), PAYLOAD, headers(MSG_ID, timestamp, signature)));
	}

	@Test
	public void verifyTamperedPayloadThrowsException() throws Exception {
		long timestamp = now();
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		assertThrows(WebhookVerificationException.class,
			verify(webhook(PUBLIC_KEY), PAYLOAD + " ", headers(MSG_ID, timestamp, signature)));
	}

	@Test
	public void verifySymmetricSignatureVersionThrowsException() throws Exception {
		long timestamp = now();
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		String header = "v1," + signature.substring("v2a,".length());
		assertThrows(WebhookVerificationException.class,
			verify(webhook(PUBLIC_KEY), PAYLOAD, headers(MSG_ID, timestamp, header)));
	}

	@Test
	public void verifyMissingHeadersThrowsException() throws Exception {
		long timestamp = now();
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		for (String header : Arrays.asList("webhook-id", "webhook-timestamp", "webhook-signature")) {
			Map<String, List<String>> headers = headers(MSG_ID, timestamp, signature);
			headers.remove(header);
			assertThrows(WebhookVerificationException.class, verify(webhook(PUBLIC_KEY), PAYLOAD, headers));
		}
	}

	@Test
	public void verifyOldTimestampThrowsException() throws Exception {
		long timestamp = now() - (5 * 60 + 1);
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		assertThrows(WebhookVerificationException.class,
			verify(webhook(PUBLIC_KEY), PAYLOAD, headers(MSG_ID, timestamp, signature)));
	}

	@Test
	public void verifyNewTimestampThrowsException() throws Exception {
		long timestamp = now() + (5 * 60 + 1);
		String signature = sign(secretKey(), ENDPOINT_ID, MSG_ID, timestamp, PAYLOAD);
		assertThrows(WebhookVerificationException.class,
			verify(webhook(PUBLIC_KEY), PAYLOAD, headers(MSG_ID, timestamp, signature)));
	}

	@Test
	public void verifyConstructorErrors() {
		List<String> keys = Collections.singletonList(PUBLIC_KEY);
		assertThrows(EmptyWebhookSecretException.class, construct(ENDPOINT_ID, Collections.<String>emptyList()));
		assertThrows(IllegalArgumentException.class,
			construct(ENDPOINT_ID, Collections.singletonList(PUBLIC_KEY.substring("whpk_".length()))));
		assertThrows(IllegalArgumentException.class,
			construct(ENDPOINT_ID, Collections.singletonList("whsec_uWKK13PfwqyOgrqT0OrWKcS2uVD7e89+oUKnkoPjx7w=")));
		assertThrows(IllegalArgumentException.class,
			construct(ENDPOINT_ID, Collections.singletonList("whpk_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")));
		assertThrows(IllegalArgumentException.class, construct(ENDPOINT_ID, Collections.singletonList("whpk_not base64!")));
		assertThrows(IllegalArgumentException.class, construct("", keys));
		assertThrows(IllegalArgumentException.class, construct("ep_1.2", keys));
	}

	@Test
	public void verifyChallengeResponseWorks() throws WebhookSigningException, EmptyWebhookSecretException {
		assertEquals(CHALLENGE_RESPONSE, webhook(PUBLIC_KEY).endpointVerificationResponse(CHALLENGE));
		// Uses the first (newest) key
		assertEquals(CHALLENGE_RESPONSE, webhook(PUBLIC_KEY, OTHER_PUBLIC_KEY).endpointVerificationResponse(CHALLENGE));
		assertTrue(!CHALLENGE_RESPONSE.equals(webhook(OTHER_PUBLIC_KEY, PUBLIC_KEY).endpointVerificationResponse(CHALLENGE)));
	}

	@Test
	public void verifyChallengeResponseVerificationKey() throws Exception {
		byte[] publicKey = Base64.getDecoder().decode(PUBLIC_KEY.substring("whpk_".length()));
		byte[] endpointId = ("." + ENDPOINT_ID).getBytes(StandardCharsets.UTF_8);
		byte[] endpointKey = new byte[publicKey.length + endpointId.length];
		System.arraycopy(publicKey, 0, endpointKey, 0, publicKey.length);
		System.arraycopy(endpointId, 0, endpointKey, publicKey.length, endpointId.length);

		javax.crypto.Mac hmac = javax.crypto.Mac.getInstance("HmacSHA256");
		hmac.init(new javax.crypto.spec.SecretKeySpec(endpointKey, "HmacSHA256"));
		byte[] verificationKey = hmac.doFinal("wev-v1".getBytes(StandardCharsets.UTF_8));
		assertArrayEquals(Base64.getDecoder().decode("YYCPt0lD/zon3FFk7MHznJHji3Td5EEGcithf+hw924="), verificationKey);
	}

	@Test
	public void verifyChallengeResponseVerifiesWorks() throws WebhookVerificationException, EmptyWebhookSecretException {
		final WebhookAsymmetric webhook = webhook(OTHER_PUBLIC_KEY, PUBLIC_KEY);

		webhook.verifyEndpointVerificationResponse(CHALLENGE, CHALLENGE_RESPONSE);
		assertThrows(WebhookVerificationException.class, new ThrowingRunnable() {
			@Override
			public void run() throws WebhookVerificationException {
				webhook.verifyEndpointVerificationResponse(CHALLENGE, "v1," + CHALLENGE_RESPONSE.substring("v2a,".length()));
			}
		});
		assertThrows(WebhookVerificationException.class, new ThrowingRunnable() {
			@Override
			public void run() throws WebhookVerificationException {
				webhook.verifyEndpointVerificationResponse("wrong", CHALLENGE_RESPONSE);
			}
		});
		assertThrows(WebhookVerificationException.class, new ThrowingRunnable() {
			@Override
			public void run() throws WebhookVerificationException {
				webhook.verifyEndpointVerificationResponse(CHALLENGE, null);
			}
		});
		assertThrows(WebhookVerificationException.class, new ThrowingRunnable() {
			@Override
			public void run() throws WebhookVerificationException, EmptyWebhookSecretException {
				webhook(OTHER_PUBLIC_KEY).verifyEndpointVerificationResponse(CHALLENGE, CHALLENGE_RESPONSE);
			}
		});
	}
}
