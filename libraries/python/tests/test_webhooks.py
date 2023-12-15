import base64
import typing as t
from datetime import datetime, timedelta, timezone
from math import floor

import pytest

from standardwebhooks.webhooks import Webhook, WebhookVerificationError, hmac_data

defaultMsgID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
defaultPayload = '{"test": 2432232314}'
defaultSecret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"

tolerance = timedelta(minutes=5)


class PayloadForTesting:
    id: str
    timestamp: str
    payload: str
    secret: str
    signature: str
    header: t.Dict[str, str]

    def __init__(self, timestamp: datetime = datetime.now(tz=timezone.utc)):
        ts = str(floor(timestamp.timestamp()))
        to_sign = f"{defaultMsgID}.{ts}.{defaultPayload}".encode()
        signature = base64.b64encode(hmac_data(base64.b64decode(defaultSecret), to_sign)).decode("utf-8")

        self.id = defaultMsgID
        self.timestamp = ts
        self.payload = defaultPayload
        self.secret = defaultSecret
        self.signature = signature
        self.header = {
            "webhook-id": defaultMsgID,
            "webhook-signature": "v1," + signature,
            "webhook-timestamp": self.timestamp,
        }


def test_missing_id_raises_error() -> None:
    testPayload = PayloadForTesting()
    del testPayload.header["webhook-id"]

    wh = Webhook(testPayload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(testPayload.payload, testPayload.header)


def test_timestamp_raises_error() -> None:
    testPayload = PayloadForTesting()
    del testPayload.header["webhook-timestamp"]

    wh = Webhook(testPayload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(testPayload.payload, testPayload.header)


def test_invalid_timestamp_raises_error() -> None:
    testPayload = PayloadForTesting()
    testPayload.header["webhook-timestamp"] = "hello"

    wh = Webhook(testPayload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(testPayload.payload, testPayload.header)


def test_missing_signature_raises_error() -> None:
    testPayload = PayloadForTesting()
    del testPayload.header["webhook-signature"]

    wh = Webhook(testPayload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(testPayload.payload, testPayload.header)


def test_invalid_signature_raises_error() -> None:
    testPayload = PayloadForTesting()
    testPayload.header["webhook-signature"] = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA="

    wh = Webhook(testPayload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(testPayload.payload, testPayload.header)


def test_valid_signature_is_valid_and_returns_json() -> None:
    testPayload = PayloadForTesting()

    wh = Webhook(testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.header)
    assert json["test"] == 2432232314


def test_valid_unbranded_signature_is_valid_and_returns_json() -> None:
    testPayload = PayloadForTesting()

    unbrandedHeaders = {
        "webhook-id": testPayload.header["webhook-id"],
        "webhook-signature": testPayload.header["webhook-signature"],
        "webhook-timestamp": testPayload.header["webhook-timestamp"],
    }
    testPayload.header = unbrandedHeaders

    wh = Webhook(testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.header)
    assert json["test"] == 2432232314


def test_old_timestamp_fails() -> None:
    testPayload = PayloadForTesting(datetime.now(tz=timezone.utc) - tolerance - timedelta(seconds=1))

    wh = Webhook(testPayload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(testPayload.payload, testPayload.header)


def test_new_timestamp_fails() -> None:
    testPayload = PayloadForTesting(datetime.now(tz=timezone.utc) + tolerance + timedelta(seconds=1))

    wh = Webhook(testPayload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(testPayload.payload, testPayload.header)


def test_multi_sig_payload_is_valid() -> None:
    testPayload = PayloadForTesting()
    sigs = [
        "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
        "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
        testPayload.header["webhook-signature"],  # valid signature
        "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    ]
    testPayload.header["webhook-signature"] = " ".join(sigs)

    wh = Webhook(testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.header)
    assert json["test"] == 2432232314


def test_signature_verification_with_and_without_prefix() -> None:
    testPayload = PayloadForTesting()

    wh = Webhook(testPayload.secret)
    json = wh.verify(testPayload.payload, testPayload.header)
    assert json["test"] == 2432232314

    wh = Webhook("whsec_" + testPayload.secret)

    json = wh.verify(testPayload.payload, testPayload.header)
    assert json["test"] == 2432232314


def test_sign_function() -> None:
    key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    msg_id = "msg_p5jXN8AQM9LWM0D4loKWxJek"
    timestamp = datetime.utcfromtimestamp(1614265330)
    payload = '{"test": 2432232314}'
    expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="

    wh = Webhook(key)
    signature = wh.sign(msg_id=msg_id, timestamp=timestamp, data=payload)
    print(signature)
    assert signature == expected
