import base64
import hashlib
import hmac
import typing

from datetime import datetime
from datetime import timezone
from math import floor

from standardwebhooks import WEBHOOK_SECRET_ENCODING


DEFAULT_MSG_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
DEFAULT_PAYLOAD = '{"test": 2432232314}'
DEFAULT_SECRET = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"


class PayloadForTesting:
    id: str
    timestamp: str
    payload: str
    secret: str
    signature: str
    header: typing.Dict[str, str]

    def __init__(self, timestamp: datetime = datetime.now(tz=timezone.utc)):
        timestamp = str(floor(timestamp.timestamp()))
        sig = f"{DEFAULT_MSG_ID}.{timestamp}.{DEFAULT_PAYLOAD}".encode()
        secret_b64 = base64.b64decode(DEFAULT_SECRET)
        sig_hmac = hmac.new(secret_b64, sig, hashlib.sha256).digest()
        sig_hmac_b64 = base64.b64encode(sig_hmac).decode(WEBHOOK_SECRET_ENCODING)

        self.header = {
            "webhook-id": DEFAULT_MSG_ID,
            "webhook-signature": "v1," + sig_hmac_b64,
            "webhook-timestamp": timestamp,
        }
        self.id = DEFAULT_MSG_ID
        self.payload = DEFAULT_PAYLOAD
        self.secret = DEFAULT_SECRET
        self.signature = sig_hmac_b64
        self.timestamp = timestamp
