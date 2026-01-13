package com.standardwebhooks;

import java.net.http.HttpHeaders;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.standardwebhooks.exceptions.WebhookVerificationException;

/**
 * Java 11+ Webhook implementation using HttpHeaders.
 */
public final class Webhook extends WebhookBase {

	public Webhook(final String secret) {
		super(secret);
	}

	public Webhook(final byte[] secret) {
		super(secret);
	}

	/**
	 * Verify webhook signature using HttpHeaders (Java 11+).
	 *
	 * @param payload The webhook payload to verify
	 * @param headers HttpHeaders containing webhook headers
	 * @throws WebhookVerificationException if verification fails
	 */
	public void verify(final String payload, final HttpHeaders headers) throws WebhookVerificationException {
		// Convert HttpHeaders to Map for base class verify method
		verify(payload, headers.map());
	}
}
