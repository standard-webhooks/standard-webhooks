package com.standardwebhooks;

/**
 *  A class for verifying and generating webhook signatures.
 */
public final class Webhook extends WebhookBase {

	public Webhook(final String secret) {
		super(secret);
	}

	public Webhook(final byte[] secret) {
		super(secret);
	}
}
