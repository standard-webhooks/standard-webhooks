package com.standardwebhooks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import com.standardwebhooks.exceptions.WebhookVerificationException;
import com.standardwebhooks.exceptions.WebhookSigningException;

import org.junit.Test;
import org.junit.function.ThrowingRunnable;

/**
 * Unit tests for WebhookBase core logic.
 * Tests all business logic using the Webhook class.
 */
public class WebhookTest {

	static int classMajorVersion(Class<?> clazz) throws IOException {
		String resource = "/" + clazz.getName().replace('.', '/') + ".class";
		try (InputStream in = clazz.getResourceAsStream(resource)) {
			if (in == null) {
				throw new IllegalStateException("Cannot find class resource: " + resource);
			}

			byte[] header = new byte[8];
			int read = in.read(header);
			if (read < 8) {
				throw new EOFException("Not enough bytes for class header");
			}

			// bytes 6–7 = major version (big-endian)
			return ((header[6] & 0xFF) << 8) | (header[7] & 0xFF);
		}
	}



	@Test
	public void verifyValidPayloadAndHeaders() throws WebhookVerificationException {
		TestScenario scenario = TestScenario.valid();
		Webhook webhook = new Webhook(scenario.secret);

		webhook.verify(scenario.payload, scenario.headersAsMap());
	}

	@Test
	public void verifyValidPayloadWithMultipleSignaturesIsValid() throws WebhookVerificationException {
		TestScenario scenario = TestScenario.valid().withMultipleSignatures();

		Webhook webhook = new Webhook(scenario.secret);
		webhook.verify(scenario.payload, scenario.headersAsMap());
	}

	@Test
	public void verifyMissingIdThrowsException() {
		TestScenario scenario = TestScenario.valid().withMissingId();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifyMissingTimestampThrowsException() {
		TestScenario scenario = TestScenario.valid().withMissingTimestamp();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifyMissingSignatureThrowsException() {
		TestScenario scenario = TestScenario.valid().withMissingSignature();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifySignatureWithDifferentVersionThrowsException() {
		TestScenario scenario = TestScenario.valid().withWrongVersion();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifyMissingPartsInSignatureThrowsException() {
		TestScenario scenario = TestScenario.valid().withInvalidSignatureFormat();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifySignatureMismatchThrowsException() {
		TestScenario scenario = TestScenario.valid().withInvalidSignatureValue();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifyOldTimestampThrowsException() {
		TestScenario scenario = TestScenario.valid().withOldTimestamp();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifyNewTimestampThrowsException() {
		TestScenario scenario = TestScenario.valid().withFutureTimestamp();
		assertThrows(WebhookVerificationException.class, verify(scenario));
	}

	@Test
	public void verifySecretWorksWithOrWithoutPrefix() throws WebhookVerificationException {
		TestScenario scenario = TestScenario.valid();

		Webhook webhook = new Webhook(scenario.secret);
		webhook.verify(scenario.payload, scenario.headersAsMap());

		webhook = new Webhook(String.format("%s%s", WebhookBase.SECRET_PREFIX, scenario.secret));
		webhook.verify(scenario.payload, scenario.headersAsMap());
	}

	@Test
	public void verifyCaseInsensitiveHeaders() throws WebhookVerificationException {
		TestScenario scenario = TestScenario.valid().withMixedCaseHeaders();

		Webhook webhook = new Webhook(scenario.secret);
		webhook.verify(scenario.payload, scenario.headersAsMap());
	}

	@Test
	public void verifyWebhookSignWorks() throws WebhookSigningException {
		TestScenario scenario = TestScenario.validSigned();
		Webhook webhook = new Webhook(scenario.secret);
		String signature = webhook.sign(scenario.id, Long.parseLong(scenario.timestamp), scenario.payload);
		assertEquals(signature, scenario.signature);
	}

	private ThrowingRunnable verify(final TestScenario scenario) {
		return new ThrowingRunnable() {
			@Override
			public void run() throws WebhookVerificationException {
				Webhook webhook = new Webhook(scenario.secret);
				webhook.verify(scenario.payload, scenario.headersAsMap());
			}
		};
	}
}
