<?php

namespace StandardWebhooks;

final class WebhookTest extends \PHPUnit\Framework\TestCase
{
    private const TOLERANCE = 5 * 60;

    public function testValidSignatureIsValidAndReturnsJson()
    {
        $testPayload = new TestPayload(time());

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $json = $wh->verify($testPayload->payload, $testPayload->header);

        $this->assertEquals(
            $json['test'],
            2432232315,
            "did not return expected json"
        );
    }

    public function testValidBrandlessSignatureIsValidAndReturnsJson()
    {
        $testPayload = new TestPayload(time());
        $unbrandedHeaders = array(
            "webhook-id" => $testPayload->header['webhook-id'],
            "webhook-signature" => $testPayload->header['webhook-signature'],
            "webhook-timestamp" => $testPayload->header['webhook-timestamp'],
        );
        $testPayload->header = $unbrandedHeaders;

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $json = $wh->verify($testPayload->payload, $testPayload->header);

        $this->assertEquals(
            $json['test'],
            2432232315,
            "did not return expected json"
        );
    }

    public function testInvalidSignatureThrowsException()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookVerificationException::class);
        $this->expectExceptionMessage("No matching signature found");

        $testPayload = new TestPayload(time());
        $testPayload->header['webhook-signature'] = 'v1,dawfeoifkpqwoekfpqoekf';

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testMissingIdThrowsException()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookVerificationException::class);
        $this->expectExceptionMessage("Missing required headers");

        $testPayload = new TestPayload(time());
        unset($testPayload->header['webhook-id']);

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testMissingTimestampThrowsException()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookVerificationException::class);
        $this->expectExceptionMessage("Missing required headers");

        $testPayload = new TestPayload(time());
        unset($testPayload->header['webhook-timestamp']);

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testMissingSignatureThrowsException()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookVerificationException::class);
        $this->expectExceptionMessage("Missing required headers");

        $testPayload = new TestPayload(time());
        unset($testPayload->header['webhook-signature']);

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testOldTimestampThrowsException()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookVerificationException::class);
        $this->expectExceptionMessage("Message timestamp too old");

        $testPayload = new TestPayload(time() - self::TOLERANCE - 1);

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testNewTimestampThrowsException()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookVerificationException::class);
        $this->expectExceptionMessage("Message timestamp too new");

        $testPayload = new TestPayload(time() + self::TOLERANCE + 1);

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testMultiSigPayloadIsValid()
    {
        $this->expectNotToPerformAssertions();

        $testPayload = new TestPayload(time());
        $sigs = [
            "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
            "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
            $testPayload->header['webhook-signature'], // valid signature
            "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
        ];
        $testPayload->header['webhook-signature'] = implode(" ", $sigs);

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testSignatureVerificationWithAndWithoutPrefix()
    {
        $this->expectNotToPerformAssertions();

        $testPayload = new TestPayload(time());

        $wh = new \StandardWebhooks\Webhook($testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);


        $wh = new \StandardWebhooks\Webhook("whsec_" . $testPayload->secret);
        $wh->verify($testPayload->payload, $testPayload->header);
    }

    public function testSignFunctionWorks()
    {
        $key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        $msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
        $timestamp = 1614265330;
        $payload = '{"test": 2432232314}';
        $expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

        $wh = new \StandardWebhooks\Webhook($key);

        $signature = $wh->sign($msgId, $timestamp, $payload);
        $this->assertEquals(
            $signature,
            $expected,
            "did not return expected signature"
        );
    }

    public function testInvalidFloatTimestamp()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookSigningException::class);
        $key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        $msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
        $timestamp = "161426533.0";
        $payload = '{"test": 2432232314}';
        $expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

        $wh = new \StandardWebhooks\Webhook($key);

        $signature = $wh->sign($msgId, $timestamp, $payload);
    }

    public function testInvalidStringTimestamp()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookSigningException::class);
        $key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        $msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
        $timestamp = "invalid timestamp";
        $payload = '{"test": 2432232314}';
        $expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

        $wh = new \StandardWebhooks\Webhook($key);

        $signature = $wh->sign($msgId, $timestamp, $payload);
    }

    public function testInvalidNegativeTimestamp()
    {
        $this->expectException(\StandardWebhooks\Exception\WebhookSigningException::class);
        $key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        $msgId = "msg_p5jXN8AQM9LWM0D4loKWxJek";
        $timestamp = "-161426533";
        $payload = '{"test": 2432232314}';
        $expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

        $wh = new \StandardWebhooks\Webhook($key);

        $signature = $wh->sign($msgId, $timestamp, $payload);
    }
}
