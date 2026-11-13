package com.standardwebhooks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import com.standardwebhooks.exceptions.EmptyWebhookSecretException;
import com.standardwebhooks.exceptions.WebhookSigningException;
import com.standardwebhooks.exceptions.WebhookVerificationException;

/**
 * Base class containing all shared asymmetric (v2a) webhook verification logic.
 * This class is used by the all java verion implementations.
 * Package-private to prevent extension outside this package.
 */
abstract class WebhookAsymmetricBase {
	public static final String PUBLIC_KEY_PREFIX = "whpk_";
	private static final String SIGNATURE_VERSION = "v2a";
	private static final String SIGNATURE_PREFIX = SIGNATURE_VERSION + ",";
	private static final int SIGNATURE_LENGTH = 64;

	private final List<byte[]> publicKeys;
	private final List<Ed25519PublicKeyParameters> publicKeyParameters;
	private final String endpointId;

	protected WebhookAsymmetricBase(final String endpointId, final List<String> publicKeys)
			throws EmptyWebhookSecretException {
		if (publicKeys == null || publicKeys.isEmpty()) {
			throw new EmptyWebhookSecretException("Webhook public keys should not be empty");
		}
		if (endpointId == null || endpointId.isEmpty()) {
			throw new IllegalArgumentException("Endpoint ID should not be empty");
		}
		if (endpointId.contains(".")) {
			throw new IllegalArgumentException("Endpoint ID must not contain '.'");
		}

		List<byte[]> keys = new ArrayList<>(publicKeys.size());
		List<Ed25519PublicKeyParameters> parameters = new ArrayList<>(publicKeys.size());
		for (String publicKey : publicKeys) {
			if (publicKey == null || !publicKey.startsWith(PUBLIC_KEY_PREFIX)) {
				throw new IllegalArgumentException(String.format("Webhook public key must start with %s", PUBLIC_KEY_PREFIX));
			}
			byte[] key = Base64.getDecoder().decode(publicKey.substring(PUBLIC_KEY_PREFIX.length()));
			if (key.length != Ed25519PublicKeyParameters.KEY_SIZE) {
				throw new IllegalArgumentException(
					String.format("Webhook public key must be %d bytes", Ed25519PublicKeyParameters.KEY_SIZE));
			}
			keys.add(key);
			parameters.add(new Ed25519PublicKeyParameters(key, 0));
		}

		this.publicKeys = Collections.unmodifiableList(keys);
		this.publicKeyParameters = Collections.unmodifiableList(parameters);
		this.endpointId = endpointId;
	}

	/**
	 * Verify webhook signature using Map-based headers (Java 8 compatible).
	 *
	 * @param payload The webhook payload to verify
	 * @param headers Map of header names to list of values
	 * @throws WebhookVerificationException if verification fails
	 */
	public final void verify(final String payload, final Map<String, List<String>> headers) throws WebhookVerificationException {
		String msgId = WebhookBase.getFirstHeader(headers, WebhookBase.UNBRANDED_MSG_ID_KEY);
		String msgSignature = WebhookBase.getFirstHeader(headers, WebhookBase.UNBRANDED_MSG_SIGNATURE_KEY);
		String msgTimestamp = WebhookBase.getFirstHeader(headers, WebhookBase.UNBRANDED_MSG_TIMESTAMP_KEY);

		if (msgId == null || msgSignature == null || msgTimestamp == null) {
			throw new WebhookVerificationException("Missing required headers");
		}

		long timestamp = WebhookBase.verifyTimestamp(msgTimestamp);

		this.verifySignature(msgId, timestamp, payload, msgSignature);
	}

	/**
	 * Verify the signature header against the given message, without checking the timestamp.
	 */
	final void verifySignature(final String msgId, final long timestamp, final String payload, final String msgSignature)
			throws WebhookVerificationException {
		byte[] digest;
		try {
			String content = String.format("%s.%s.%s.%s", this.endpointId, msgId, timestamp, payload);
			digest = MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new WebhookVerificationException("Failed to generate expected signature");
		}

		for (String versionedSignature : msgSignature.split(" ")) {
			if (!versionedSignature.startsWith(SIGNATURE_PREFIX)) {
				continue;
			}

			byte[] signature;
			try {
				signature = Base64.getDecoder().decode(versionedSignature.substring(SIGNATURE_PREFIX.length()));
			} catch (IllegalArgumentException e) {
				continue;
			}
			if (signature.length != SIGNATURE_LENGTH) {
				continue;
			}

			for (Ed25519PublicKeyParameters publicKey : this.publicKeyParameters) {
				Ed25519Signer verifier = new Ed25519Signer();
				verifier.init(false, publicKey);
				verifier.update(digest, 0, digest.length);
				if (verifier.verifySignature(signature)) {
					return;
				}
			}
		}
		throw new WebhookVerificationException("No matching signature found");
	}

	/**
	 * Calculate the response to an endpoint verification challenge, using the
	 * first (newest) public key.
	 *
	 * @param challenge The value of the webhook-challenge request header
	 * @return The value for the webhook-challenge-response response header
	 * @throws WebhookSigningException if the response can't be calculated
	 */
	public final String endpointVerificationResponse(final String challenge) throws WebhookSigningException {
		return this.endpointVerificationResponse(this.publicKeys.get(0), challenge);
	}

	/**
	 * Verify the response to an endpoint verification challenge. The response is
	 * accepted if it was calculated with any of the public keys.
	 *
	 * @param challenge The challenge sent in the webhook-challenge request header
	 * @param header The value of the webhook-challenge-response response header
	 * @throws WebhookVerificationException if verification fails
	 */
	public final void verifyEndpointVerificationResponse(final String challenge, final String header) throws WebhookVerificationException {
		if (challenge == null || header == null) {
			throw new WebhookVerificationException("Missing challenge response");
		}

		byte[] headerBytes = header.getBytes(StandardCharsets.UTF_8);
		boolean found = false;
		for (byte[] publicKey : this.publicKeys) {
			String expectedSignature;
			try {
				expectedSignature = this.endpointVerificationResponse(publicKey, challenge);
			} catch (WebhookSigningException e) {
				throw new WebhookVerificationException("Failed to generate expected signature");
			}
			found |= MessageDigest.isEqual(headerBytes, expectedSignature.getBytes(StandardCharsets.UTF_8));
		}

		if (!found) {
			throw new WebhookVerificationException("No matching signature found");
		}
	}

	private String endpointVerificationResponse(final byte[] publicKey, final String challenge) throws WebhookSigningException {
		byte[] endpointIdBytes = ("." + this.endpointId).getBytes(StandardCharsets.UTF_8);
		byte[] endpointKey = new byte[publicKey.length + endpointIdBytes.length];
		System.arraycopy(publicKey, 0, endpointKey, 0, publicKey.length);
		System.arraycopy(endpointIdBytes, 0, endpointKey, publicKey.length, endpointIdBytes.length);

		String signature = Base64.getEncoder().encodeToString(WebhookBase.endpointVerificationSignature(endpointKey, challenge));
		return String.format("%s%s", SIGNATURE_PREFIX, signature);
	}
}
