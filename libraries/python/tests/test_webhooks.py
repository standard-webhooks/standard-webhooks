import base64
import typing as t
from datetime import datetime, timedelta, timezone
from math import floor

import pytest

from standardwebhooks.webhooks import Webhook, WebhookVerificationError, hmac_data

DEFAULT_MSG_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
DEFAULT_PAYLOAD = '{"test": 2432232314}'
DEFAULT_SECRET = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"

TOLERANCE = timedelta(minutes=5)


class PayloadForTesting:
    id: str
    timestamp: str
    payload: str
    secret: str
    signature: str
    header: t.Dict[str, str]

    def __init__(self, timestamp: datetime = datetime.now(tz=timezone.utc)):
        ts = str(floor(timestamp.timestamp()))
        to_sign = f"{DEFAULT_MSG_ID}.{ts}.{DEFAULT_PAYLOAD}".encode()
        signature = base64.b64encode(hmac_data(base64.b64decode(DEFAULT_SECRET), to_sign)).decode("utf-8")

        self.id = DEFAULT_MSG_ID
        self.timestamp = ts
        self.payload = DEFAULT_PAYLOAD
        self.secret = DEFAULT_SECRET
        self.signature = signature
        self.header = {
            "webhook-id": DEFAULT_MSG_ID,
            "webhook-signature": "v1," + signature,
            "webhook-timestamp": self.timestamp,
        }


def test_missing_id_raises_error() -> None:
    test_payload = PayloadForTesting()
    del test_payload.header["webhook-id"]

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_timestamp_raises_error() -> None:
    test_payload = PayloadForTesting()
    del test_payload.header["webhook-timestamp"]

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_invalid_timestamp_raises_error() -> None:
    test_payload = PayloadForTesting()
    test_payload.header["webhook-timestamp"] = "hello"

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_missing_signature_raises_error() -> None:
    test_payload = PayloadForTesting()
    del test_payload.header["webhook-signature"]

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_invalid_signature_raises_error() -> None:
    test_payload = PayloadForTesting()
    test_payload.header["webhook-signature"] = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA="

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_valid_signature_is_valid_and_returns_json() -> None:
    test_payload = PayloadForTesting()

    wh = Webhook(test_payload.secret)

    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314


def test_valid_unbranded_signature_is_valid_and_returns_json() -> None:
    test_payload = PayloadForTesting()

    unbranded_headers = {
        "webhook-id": test_payload.header["webhook-id"],
        "webhook-signature": test_payload.header["webhook-signature"],
        "webhook-timestamp": test_payload.header["webhook-timestamp"],
    }
    test_payload.header = unbranded_headers

    wh = Webhook(test_payload.secret)

    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314


def test_old_timestamp_fails() -> None:
    test_payload = PayloadForTesting(datetime.now(tz=timezone.utc) - TOLERANCE - timedelta(seconds=1))

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_new_timestamp_fails() -> None:
    test_payload = PayloadForTesting(datetime.now(tz=timezone.utc) + TOLERANCE + timedelta(seconds=1))

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_multi_sig_payload_is_valid() -> None:
    test_payload = PayloadForTesting()
    sigs = [
        "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
        "v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
        test_payload.header["webhook-signature"],  # valid signature
        "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
    ]
    test_payload.header["webhook-signature"] = " ".join(sigs)

    wh = Webhook(test_payload.secret)

    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314


def test_signature_verification_with_and_without_prefix() -> None:
    test_payload = PayloadForTesting()

    wh = Webhook(test_payload.secret)
    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314

    wh = Webhook("whsec_" + test_payload.secret)

    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314


def test_sign_function() -> None:
    key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    msg_id = "msg_p5jXN8AQM9LWM0D4loKWxJek"
    timestamp = datetime.utcfromtimestamp(1614265330)
    payload = '{"test": 2432232314}'
    expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="

    wh = Webhook(key)
    signature = wh.sign(msg_id=msg_id, timestamp=timestamp, data=payload)
    assert signature == expected
