import base64
import hashlib
import hmac
import json
import typing as t
from datetime import datetime, timedelta, timezone
from math import floor


def hmac_data(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _payload_bytes(data: t.Union[bytes, str]) -> bytes:
    """The payload as signed: the body bytes exactly as received. A str is encoded as UTF-8."""
    if isinstance(data, str):
        return data.encode()
    # Only bytes-like objects: bytes() also turns an int or a list of ints into bytes, which
    # would sign unrelated bytes instead of failing. A memoryview must be over single bytes; one
    # over wider items (e.g. memoryview(array.array("H", ...))) is rejected rather than signed
    # as its platform-endian underlying bytes.
    if isinstance(data, (bytes, bytearray)) or (isinstance(data, memoryview) and data.itemsize == 1):
        return bytes(data)
    raise TypeError("Expected payload to be of type str or bytes")


class WebhookVerificationError(Exception):
    pass


class EmptyWebhookSecretError(Exception):
    pass


class Webhook:
    _SECRET_PREFIX: str = "whsec_"
    _whsecret: bytes

    def __init__(self, whsecret: t.Union[str, bytes]):
        if isinstance(whsecret, str):
            if whsecret.startswith(self._SECRET_PREFIX):
                whsecret = whsecret[len(self._SECRET_PREFIX) :]
            # add padding in case whsecret is unpadded base64 (b64decode skips extra padding)
            whsecret = base64.b64decode(whsecret + "==")

        if not whsecret:
            raise EmptyWebhookSecretError("webhook secret may not be empty")

        if isinstance(whsecret, bytes):
            self._whsecret = whsecret
        else:
            raise RuntimeError("Invalid webhook secret")

    def verify(
        self,
        data: t.Union[bytes, str],
        headers: t.Dict[str, str],
        *,
        json_parse: bool = True,
    ) -> t.Any:
        """
        Verify the given webhook headers against the body bytes (data).

        Pass the raw request body exactly as received. bytes are verified byte for byte, so
        bodies that aren't valid UTF-8 verify. A str is verified as its UTF-8 encoding.

        Args:
            json_parse (bool): Whether to parse the data as JSON on success (default: True)

        Returns:
            After successful verification: if json_parse is True, returns the
            JSON-parsed input data; if it json_parse False, returns None.

        Raises:
            WebhookVerificationError if one of the required headers is missing,
            invalid, too old or too new; or no matching signature is found.
        """

        payload = _payload_bytes(data)
        headers = {k.lower(): v for (k, v) in headers.items()}
        msg_id = headers.get("webhook-id")
        msg_signature = headers.get("webhook-signature")
        msg_timestamp = headers.get("webhook-timestamp")
        if not (msg_id and msg_timestamp and msg_signature):
            raise WebhookVerificationError("Missing required headers")

        timestamp = self.__verify_timestamp(msg_timestamp)

        expected_sig = self.sign(msg_id=msg_id, timestamp=timestamp, data=payload).encode()
        passed_sigs = msg_signature.split(" ")
        if not any(hmac.compare_digest(expected_sig, versioned_sig.encode()) for versioned_sig in passed_sigs):
            raise WebhookVerificationError("No matching signature found")

        if json_parse:
            return json.loads(payload)

    def sign(self, msg_id: str, timestamp: datetime, data: t.Union[bytes, str]) -> str:
        """
        Sign the given payload and return the versioned signature string.

        Args:
            msg_id: The unique message id (sent as the `webhook-id` header).
            timestamp: The message timestamp (sent as the `webhook-timestamp` header).
                Timezone-aware datetimes are converted to their POSIX timestamp, so any
                timezone can be used. Naive datetimes are interpreted as UTC.
            data: The raw payload. bytes are signed byte for byte, so bodies that aren't
                valid UTF-8 are signed as sent. A str is signed as its UTF-8 encoding.
        """
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        timestamp_str = str(floor(timestamp.timestamp()))
        to_sign = f"{msg_id}.{timestamp_str}.".encode() + _payload_bytes(data)
        signature = hmac_data(self._whsecret, to_sign)
        return f"v1,{base64.b64encode(signature).decode('utf-8')}"

    def __verify_timestamp(self, timestamp_header: str) -> datetime:
        webhook_tolerance = timedelta(minutes=5)
        now = datetime.now(tz=timezone.utc)
        try:
            timestamp = datetime.fromtimestamp(float(timestamp_header), tz=timezone.utc)
        except Exception:
            raise WebhookVerificationError("Invalid Signature Headers")

        if timestamp < (now - webhook_tolerance):
            raise WebhookVerificationError("Message timestamp too old")
        if timestamp > (now + webhook_tolerance):
            raise WebhookVerificationError("Message timestamp too new")
        return timestamp
