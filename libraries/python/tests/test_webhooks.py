import base64
import typing as t
from datetime import datetime, timedelta, timezone
from math import floor

import pytest

from standardwebhooks.webhooks import EmptyWebhookSecretError, Webhook, WebhookVerificationError, hmac_data

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

    def __init__(self, timestamp: datetime = datetime.now(tz=timezone.utc), secret: str = DEFAULT_SECRET):
        ts = str(floor(timestamp.timestamp()))
        to_sign = f"{DEFAULT_MSG_ID}.{ts}.{DEFAULT_PAYLOAD}".encode()
        signature = base64.b64encode(hmac_data(base64.b64decode(secret), to_sign)).decode("utf-8")

        self.id = DEFAULT_MSG_ID
        self.timestamp = ts
        self.payload = DEFAULT_PAYLOAD
        self.secret = secret
        self.signature = signature
        self.header = {
            "webhook-id": DEFAULT_MSG_ID,
            "webhook-signature": "v1," + signature,
            "webhook-timestamp": self.timestamp,
        }


def test_empty_secret_raises_error() -> None:
    with pytest.raises(EmptyWebhookSecretError):
        Webhook("")
    with pytest.raises(EmptyWebhookSecretError):
        Webhook(b"")
    with pytest.raises(EmptyWebhookSecretError):
        Webhook("whsec_")


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


def test_valid_signature_is_valid_without_returning_json() -> None:
    test_payload = PayloadForTesting()

    wh = Webhook(test_payload.secret)

    result = wh.verify(test_payload.payload, test_payload.header, json_parse=False)
    assert result is None


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


def test_signature_verification_with_unpadded_secret() -> None:
    # needs no padding
    secret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    test_payload = PayloadForTesting(secret=secret)

    wh = Webhook(secret)
    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314

    # needs one padding
    secret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS"
    test_payload = PayloadForTesting(secret=secret + "=")

    wh = Webhook(secret)
    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314

    # needs two padding
    secret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr"
    test_payload = PayloadForTesting(secret=secret + "==")

    wh = Webhook(secret)
    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314

    # with prefix
    wh = Webhook("whsec_" + secret)

    json = wh.verify(test_payload.payload, test_payload.header)
    assert json["test"] == 2432232314


def test_sign_function() -> None:
    key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    msg_id = "msg_p5jXN8AQM9LWM0D4loKWxJek"
    timestamp = datetime.fromtimestamp(1614265330, tz=timezone.utc)
    payload = '{"test": 2432232314}'
    expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="

    wh = Webhook(key)
    signature = wh.sign(msg_id=msg_id, timestamp=timestamp, data=payload)
    assert signature == expected


# Every byte value, so the payload is not valid UTF-8. The expected signature is the Go
# library's for the same inputs, which signs the payload bytes as given.
BINARY_PAYLOAD = bytes(range(256))
BINARY_PAYLOAD_SIGNATURE = "v1,sEcZ042G8Crqgxbybb3y0eDxQR3TcfYsk11I1XULhSI="
SIGN_TIMESTAMP = datetime.fromtimestamp(1614265330, tz=timezone.utc)


def binary_header(timestamp: str, payload: bytes) -> t.Dict[str, str]:
    to_sign = f"{DEFAULT_MSG_ID}.{timestamp}.".encode() + payload
    signature = base64.b64encode(hmac_data(base64.b64decode(DEFAULT_SECRET), to_sign)).decode("utf-8")
    return {
        "webhook-id": DEFAULT_MSG_ID,
        "webhook-signature": "v1," + signature,
        "webhook-timestamp": timestamp,
    }


def test_sign_function_binary_payload() -> None:
    wh = Webhook("whsec_" + DEFAULT_SECRET)

    assert wh.sign(msg_id=DEFAULT_MSG_ID, timestamp=SIGN_TIMESTAMP, data=BINARY_PAYLOAD) == BINARY_PAYLOAD_SIGNATURE


def test_sign_function_same_for_str_and_its_utf8_bytes() -> None:
    wh = Webhook("whsec_" + DEFAULT_SECRET)
    payload = '{"test": "ünïcödé ✓"}'

    assert wh.sign(msg_id=DEFAULT_MSG_ID, timestamp=SIGN_TIMESTAMP, data=payload.encode()) == wh.sign(
        msg_id=DEFAULT_MSG_ID, timestamp=SIGN_TIMESTAMP, data=payload
    )


def test_binary_payload_is_valid() -> None:
    timestamp = str(floor(datetime.now(tz=timezone.utc).timestamp()))
    wh = Webhook(DEFAULT_SECRET)

    assert wh.verify(BINARY_PAYLOAD, binary_header(timestamp, BINARY_PAYLOAD), json_parse=False) is None


def test_binary_payload_with_changed_byte_fails() -> None:
    timestamp = str(floor(datetime.now(tz=timezone.utc).timestamp()))
    header = binary_header(timestamp, BINARY_PAYLOAD)
    changed = BINARY_PAYLOAD[:-1] + b"\x00"
    wh = Webhook(DEFAULT_SECRET)

    with pytest.raises(WebhookVerificationError):
        wh.verify(changed, header, json_parse=False)


def test_json_payload_as_bytes_returns_json() -> None:
    test_payload = PayloadForTesting()
    wh = Webhook(test_payload.secret)

    json = wh.verify(test_payload.payload.encode(), test_payload.header)
    assert json["test"] == 2432232314
