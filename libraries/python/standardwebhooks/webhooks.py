import base64
import hashlib
import hmac

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from math import floor
from typing import Any
from typing import Dict
from typing import Union

from .config import WEBHOOK_SECRET_ENCODING
from .config import WEBHOOK_SECRET_PREFIX
from .config import WEBHOOK_TOLERANCE_SECONDS
from .config import WEBHOOK_VERSION
from .exceptions import WebhookVerificationError


class Webhook:
    secret: bytes

    def __init__(self, secret_b64: Union[str, bytes]):
        if not secret_b64:
            raise WebhookVerificationError("Secret can't be empty.")

        # Convert bytes to string
        if isinstance(secret_b64, bytes):
            secret_b64 = secret_b64.decode(WEBHOOK_SECRET_ENCODING)

        secret_b64 = secret_b64.replace(WEBHOOK_SECRET_PREFIX, "")
        self.secret = base64.b64decode(secret_b64)

    def __verify_timestamp(self, timestamp: str) -> datetime:
        try:
            timestamp = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
        except Exception:
            raise WebhookVerificationError("Invalid Signature Headers.")

        tolerance = timedelta(seconds=WEBHOOK_TOLERANCE_SECONDS)
        now = datetime.now(tz=timezone.utc)

        timestamp_to_old = timestamp < (now - tolerance)
        if timestamp_to_old:
            raise WebhookVerificationError("Message timestamp is too old.")

        timestamp_to_new = timestamp > (now + tolerance)
        if timestamp_to_new:
            raise WebhookVerificationError("Message timestamp is too new.")

        return timestamp

    def sign(self, msg_id: str, timestamp: datetime, payload: str) -> str:
        timestamp = str(floor(timestamp.replace(tzinfo=timezone.utc).timestamp()))
        sign = f"{msg_id}.{timestamp}.{payload}".encode()
        sig_hmac = hmac.new(self.secret, sign, hashlib.sha256).digest()
        sig_hmac_b64 = base64.b64encode(sig_hmac).decode("utf-8")

        return f"v1,{sig_hmac_b64}"

    def verify(self, payload: Union[bytes, str], headers: Dict[str, str]) -> Any:
        payload = payload if isinstance(payload, str) else payload.decode()
        headers = {k.lower(): v for (k, v) in headers.items()}

        msg_id = headers.get("webhook-id")
        if not msg_id:
            raise WebhookVerificationError("Missing webhook-id header.")

        msg_signature = headers.get("webhook-signature")
        if not msg_signature:
            raise WebhookVerificationError("Missing webhook-signature header.")

        msg_timestamp = headers.get("webhook-timestamp")
        if not msg_timestamp:
            raise WebhookVerificationError("Missing webhook-timestamp header.")

        timestamp = self.__verify_timestamp(msg_timestamp)

        passed_sig = msg_signature.split(" ")
        for versioned_sig in passed_sig:
            version, provided_sig = versioned_sig.split(",")

            default_version = (version == WEBHOOK_VERSION)
            if not default_version:
                continue

            provided_sig = base64.b64decode(provided_sig)
            expected_sig = self.sign(msg_id=msg_id, timestamp=timestamp, payload=payload)
            expected_sig = base64.b64decode(expected_sig.split(",")[1])

            signatures_match = hmac.compare_digest(provided_sig, expected_sig)
            if signatures_match:
                return payload

        raise WebhookVerificationError("No matching signature found.")
