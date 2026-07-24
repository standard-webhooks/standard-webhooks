import base64
import hashlib
import hmac
import json
import typing as t
from datetime import datetime, timedelta, timezone
from math import floor

import cryptography.exceptions
import cryptography.hazmat.primitives.asymmetric.ed25519


def hmac_data(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


class WebhookVerificationError(Exception):
    pass


class EmptyWebhookSecretError(Exception):
    def __init__(self) -> None:
        self.message = "webhook secret may not be empty"


class BaseWebhookSecret(object):
    VERSION: str = ""

    def verify(self, msg_id: str, timestamp: datetime, data: str, signature: bytes) -> bool:
        _ = (msg_id, timestamp, data, signature)
        raise NotImplementedError

    def sign(self, msg_id: str, timestamp: datetime, data: str) -> str:
        _ = (msg_id, timestamp, data)
        raise NotImplementedError

    def to_sign(self, msg_id: str, timestamp: datetime, data: str) -> bytes:
        timestamp_str = str(floor(timestamp.replace(tzinfo=timezone.utc).timestamp()))
        to_sign = b".".join([msg_id.encode("utf-8"), timestamp_str.encode("ascii"), data.encode("utf-8")])
        return to_sign


class HmacWebhookSecret(BaseWebhookSecret):
    VERSION: str = "v1"
    SECRET_PREFIX: str = "whsec_"
    wbsecret: bytes

    def __init__(self, whsecret: bytes):
        self.whsecret = whsecret

    def verify(self, msg_id: str, timestamp: datetime, data: str, signature: bytes) -> bool:
        expected_sig = base64.b64decode(self.sign(msg_id=msg_id, timestamp=timestamp, data=data).split(",")[1])
        return hmac.compare_digest(expected_sig, signature)

    def sign(self, msg_id: str, timestamp: datetime, data: str) -> str:
        signature = hmac_data(self.whsecret, self.to_sign(msg_id, timestamp, data))
        return f"{self.VERSION},{base64.b64encode(signature).decode('ascii')}"


class VerifyOnlyEd25519WebhookSecret(BaseWebhookSecret):
    VERSION: str = "v1a"
    SECRET_PREFIX: str = "whpk_"
    pubkey: cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey

    def __init__(self, whsecret: bytes):
        self.pubkey = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(whsecret)

    def verify(self, msg_id: str, timestamp: datetime, data: str, signature: bytes) -> bool:
        body = self.to_sign(msg_id, timestamp, data)
        try:
            self.pubkey.verify(signature, body)
            return True
        except cryptography.exceptions.InvalidSignature:
            return False

    def sign(self, msg_id: str, timestamp: datetime, data: str) -> str:
        _ = (msg_id, timestamp, data)
        raise ValueError("Cannot sign webhooks with a verify-only key")


class Ed25519WebhookSecret(VerifyOnlyEd25519WebhookSecret):
    VERSION: str = "v1a"
    SECRET_PREFIX: str = "whsk_"
    privkey: cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
    pubkey: cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey

    def __init__(self, whsecret: bytes):
        self.privkey = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(whsecret)
        self.pubkey = self.privkey.public_key()

    def sign(self, msg_id: str, timestamp: datetime, data: str) -> str:
        body = self.to_sign(msg_id, timestamp, data)
        raw_signature = self.privkey.sign(body)
        encoded = base64.b64encode(raw_signature).decode("ascii")
        return f"{self.VERSION},{encoded}"


class Webhook:
    _whsecret: BaseWebhookSecret

    def __init__(self, whsecret: t.Union[str, bytes]):
        if isinstance(whsecret, str):
            for cls in (HmacWebhookSecret, VerifyOnlyEd25519WebhookSecret, Ed25519WebhookSecret):
                if whsecret.startswith(cls.SECRET_PREFIX):
                    remainder = whsecret.removeprefix(cls.SECRET_PREFIX)
                    # add padding in case whsecret is unpadded base64 (b64decode skips extra padding)
                    raw = base64.b64decode(remainder + "==")
                    if not raw:
                        raise EmptyWebhookSecretError()
                    self._whsecret = cls(raw)
                    return
            whsecret = base64.b64decode(whsecret + "==")

        if not whsecret:
            raise EmptyWebhookSecretError()

        # legacy fallback for unprefixed secrets
        if isinstance(whsecret, bytes):
            self._whsecret = HmacWebhookSecret(whsecret)
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

        Args:
            json_parse (bool): Whether to deserialize the data to (default: True)

        Returns:
            After successful verification: if json_parse is True, returns the
            JSON-parsed input data; if it json_parse False, returns None.

        Raises:
            WebhookVerificationError if one of the required headers is missing,
            invalid, too old or too new; or no matching signature is found.
        """

        data = data if isinstance(data, str) else data.decode()
        headers = {k.lower(): v for (k, v) in headers.items()}
        msg_id = headers.get("webhook-id")
        msg_signature = headers.get("webhook-signature")
        msg_timestamp = headers.get("webhook-timestamp")
        if not (msg_id and msg_timestamp and msg_signature):
            raise WebhookVerificationError("Missing required headers")

        timestamp = self.__verify_timestamp(msg_timestamp)

        passed_sigs = msg_signature.split(" ")
        for versioned_sig in passed_sigs:
            (version, signature) = versioned_sig.split(",")
            if self._whsecret.VERSION != version:
                continue
            raw_signature = base64.b64decode(signature)
            if self._whsecret.verify(msg_id, timestamp, data, raw_signature):
                if json_parse:
                    return json.loads(data)
                else:
                    return

        raise WebhookVerificationError("No matching signature found")

    def sign(self, msg_id: str, timestamp: datetime, data: str) -> str:
        return self._whsecret.sign(msg_id, timestamp, data)

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
