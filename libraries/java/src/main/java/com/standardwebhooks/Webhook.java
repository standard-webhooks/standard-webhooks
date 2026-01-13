package com.standardwebhooks;

/**
 * Java 8 Webhook implementation.
 * Uses Map-based headers inherited from WebhookBase.
 */
public final class Webhook extends WebhookBase {

	public Webhook(final String secret) {
		super(secret);
	}

	public Webhook(final byte[] secret) {
		super(secret);
	}
}
