import base64
import hashlib
import hmac
import json
import typing as t
from datetime import datetime, timedelta, timezone
from math import floor


def hmac_data(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


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

        Args:
            json_parse (bool): Whether to parse the data as JSON on success (default: True)

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

        expected_sig = self.sign(msg_id=msg_id, timestamp=timestamp, data=data).encode()
        passed_sigs = msg_signature.split(" ")
        if not any(hmac.compare_digest(expected_sig, versioned_sig.encode()) for versioned_sig in passed_sigs):
            raise WebhookVerificationError("No matching signature found")

        if json_parse:
            return json.loads(data)

    def sign(self, msg_id: str, timestamp: datetime, data: str) -> str:
        timestamp_str = str(floor(timestamp.replace(tzinfo=timezone.utc).timestamp()))
        to_sign = f"{msg_id}.{timestamp_str}.{data}".encode()
        signature = hmac_data(self._whsecret, to_sign)
        return f"v1,{base64.b64encode(signature).decode('utf-8')}"

    def endpoint_verification_response(self, challenge: str) -> str:
        """
        Calculate the response to an endpoint verification challenge.

        Args:
            challenge (str): The value of the `webhook-challenge` request header

        Returns:
            The value for the `webhook-challenge-response` response header.
        """
        verification_key = hmac_data(self._whsecret, b"wev-v1")
        signature = hmac_data(verification_key, challenge.encode())
        return f"v1,{base64.b64encode(signature).decode('utf-8')}"

    def verify_endpoint_verification_response(self, challenge: str, header: str) -> None:
        """
        Verify the response to an endpoint verification challenge.

        Args:
            challenge (str): The challenge sent in the `webhook-challenge` request header
            header (str): The value of the `webhook-challenge-response` response header

        Raises:
            WebhookVerificationError if no matching signature is found.
        """
        expected_sig = self.endpoint_verification_response(challenge)
        if not hmac.compare_digest(expected_sig.encode(), header.encode()):
            raise WebhookVerificationError("No matching signature found")

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
