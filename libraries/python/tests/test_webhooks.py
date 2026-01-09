import pytest

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from standardwebhooks import WEBHOOK_TOLERANCE_SECONDS
from standardwebhooks import WebhookVerificationError
from standardwebhooks import Webhook

from .fixtures import PayloadForTesting


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


def test_valid_signature_is_valid() -> None:
    test_payload = PayloadForTesting()

    wh = Webhook(test_payload.secret)

    payload = wh.verify(test_payload.payload, test_payload.header)
    assert "2432232314" in payload


def test_valid_unbranded_signature_is_valid() -> None:
    test_payload = PayloadForTesting()

    unbranded_headers = {
        "webhook-id": test_payload.header["webhook-id"],
        "webhook-signature": test_payload.header["webhook-signature"],
        "webhook-timestamp": test_payload.header["webhook-timestamp"],
    }
    test_payload.header = unbranded_headers

    wh = Webhook(test_payload.secret)

    payload = wh.verify(test_payload.payload, test_payload.header)
    assert "2432232314" in payload


def test_old_timestamp_fails() -> None:
    old_timestamp = datetime.now(tz=timezone.utc) - timedelta(seconds=WEBHOOK_TOLERANCE_SECONDS + 1)
    test_payload = PayloadForTesting(old_timestamp)

    wh = Webhook(test_payload.secret)

    with pytest.raises(WebhookVerificationError):
        wh.verify(test_payload.payload, test_payload.header)


def test_new_timestamp_fails() -> None:
    new_timestamp = datetime.now(tz=timezone.utc) + timedelta(seconds=WEBHOOK_TOLERANCE_SECONDS + 1)
    test_payload = PayloadForTesting(new_timestamp)

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

    payload = wh.verify(test_payload.payload, test_payload.header)
    assert "2432232314" in payload


def test_signature_verification_with_and_without_prefix() -> None:
    test_payload = PayloadForTesting()

    wh = Webhook(test_payload.secret)

    payload = wh.verify(test_payload.payload, test_payload.header)
    assert "2432232314" in payload

    wh = Webhook("whsec_" + test_payload.secret)

    payload = wh.verify(test_payload.payload, test_payload.header)
    assert "2432232314" in payload


def test_sign_function() -> None:
    expected = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
    key = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    msg_id = "msg_p5jXN8AQM9LWM0D4loKWxJek"
    payload = '{"test": 2432232314}'
    timestamp = datetime.utcfromtimestamp(1614265330)

    wh = Webhook(key)
    signature = wh.sign(msg_id=msg_id, timestamp=timestamp, payload=payload)
    assert signature == expected
