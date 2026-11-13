import base64
import binascii
import hashlib
import hmac
import json
import typing as t
from datetime import datetime, timedelta, timezone
from math import floor

if t.TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


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


def _parse_headers(headers: t.Dict[str, str]) -> t.Tuple[str, str, datetime]:
    """Normalize the headers (case-insensitive names), and check the timestamp is in tolerance.

    Returns the message id, the signature header and the timestamp.
    """
    headers = {k.lower(): v for (k, v) in headers.items()}
    msg_id = headers.get("webhook-id")
    msg_signature = headers.get("webhook-signature")
    msg_timestamp = headers.get("webhook-timestamp")
    if not (msg_id and msg_timestamp and msg_signature):
        raise WebhookVerificationError("Missing required headers")

    return msg_id, msg_signature, _verify_timestamp(msg_timestamp)


def _verify_timestamp(timestamp_header: str) -> datetime:
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


def _timestamp_str(timestamp: datetime) -> str:
    """The integer timestamp, as signed. Naive datetimes are interpreted as UTC."""
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return str(floor(timestamp.timestamp()))


def _challenge_response(endpoint_key: bytes, challenge: str, identifier: str) -> str:
    """The response to an endpoint verification challenge, for the given endpoint key."""
    verification_key = hmac_data(endpoint_key, b"wev-v1")
    signature = hmac_data(verification_key, challenge.encode())
    return f"{identifier},{base64.b64encode(signature).decode('utf-8')}"


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
        msg_id, msg_signature, timestamp = _parse_headers(headers)

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
        to_sign = f"{msg_id}.{_timestamp_str(timestamp)}.".encode() + _payload_bytes(data)
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
        return _challenge_response(self._whsecret, challenge, "v1")

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


def _import_ed25519() -> t.Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:
        raise ImportError(
            "WebhookAsymmetric requires the 'cryptography' package. "
            "Install it with: pip install 'standardwebhooks[asymmetric]'"
        ) from e
    return ed25519


class WebhookAsymmetric:
    """
    Verify webhooks signed with asymmetric (`v2a`, ed25519) signatures.

    Only verification is supported: producers are expected to sign using a KMS or an HSM.

    Requires the `asymmetric` extra: `pip install 'standardwebhooks[asymmetric]'`.
    """

    _PUBLIC_KEY_PREFIX: str = "whpk_"
    _public_keys: t.List[bytes]
    _verifiers: t.List["Ed25519PublicKey"]
    _endpoint_id: str

    def __init__(self, endpoint_id: str, public_keys: t.List[str]):
        """
        Args:
            endpoint_id: The endpoint ID the producer shared with you together with the
                public key. Never take it from the request.
            public_keys: The producer's trusted public keys (`whpk_...`). Webhooks signed with
                any of them are accepted, so keys can be rotated by adding the new key to the
                list. The first key must be the newest one: it's the one used for endpoint
                verification.
        """
        ed25519 = _import_ed25519()

        if isinstance(public_keys, str) or not public_keys:
            raise RuntimeError("Public keys may not be empty")

        self._public_keys = []
        self._verifiers = []
        for public_key in public_keys:
            if not isinstance(public_key, str) or not public_key.startswith(self._PUBLIC_KEY_PREFIX):
                raise RuntimeError(f"Invalid public key: must start with '{self._PUBLIC_KEY_PREFIX}'")
            try:
                key = base64.b64decode(public_key[len(self._PUBLIC_KEY_PREFIX) :], validate=True)
            except binascii.Error:
                raise RuntimeError("Invalid public key: not valid base64")
            if len(key) != 32:
                raise RuntimeError(f"Invalid public key: must be 32 bytes, got {len(key)}")
            try:
                verifier = ed25519.Ed25519PublicKey.from_public_bytes(key)
            except ValueError:
                raise RuntimeError("Invalid public key: not a valid ed25519 public key")
            self._public_keys.append(key)
            self._verifiers.append(verifier)

        if not isinstance(endpoint_id, str) or not endpoint_id:
            raise RuntimeError("Endpoint ID may not be empty")
        if "." in endpoint_id:
            raise RuntimeError("Endpoint ID may not contain '.'")
        self._endpoint_id = endpoint_id

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
        from cryptography.exceptions import InvalidSignature

        payload = _payload_bytes(data)
        msg_id, msg_signature, timestamp = _parse_headers(headers)

        content = f"{self._endpoint_id}.{msg_id}.{_timestamp_str(timestamp)}.".encode() + payload
        digest = hashlib.sha256(content).digest()

        for versioned_sig in msg_signature.split(" "):
            version, _, encoded_sig = versioned_sig.partition(",")
            if version != "v2a":
                continue
            try:
                signature = base64.b64decode(encoded_sig, validate=True)
            except binascii.Error:
                continue
            if len(signature) != 64:
                continue
            for verifier in self._verifiers:
                try:
                    verifier.verify(signature, digest)
                except InvalidSignature:
                    continue
                if json_parse:
                    return json.loads(payload)
                return None

        raise WebhookVerificationError("No matching signature found")

    def endpoint_verification_response(self, challenge: str) -> str:
        """
        Calculate the response to an endpoint verification challenge, using the first
        (newest) public key.

        Args:
            challenge (str): The value of the `webhook-challenge` request header

        Returns:
            The value for the `webhook-challenge-response` response header.
        """
        return self.__challenge_response(self._public_keys[0], challenge)

    def verify_endpoint_verification_response(self, challenge: str, header: str) -> None:
        """
        Verify the response to an endpoint verification challenge. The response is accepted
        if it matches any of the public keys.

        Args:
            challenge (str): The challenge sent in the `webhook-challenge` request header
            header (str): The value of the `webhook-challenge-response` response header

        Raises:
            WebhookVerificationError if no matching signature is found.
        """
        passed = header.encode()
        found = False
        for public_key in self._public_keys:
            expected_sig = self.__challenge_response(public_key, challenge)
            # Not short-circuiting, so the time taken doesn't depend on which key matched.
            found = hmac.compare_digest(expected_sig.encode(), passed) or found
        if not found:
            raise WebhookVerificationError("No matching signature found")

    def __challenge_response(self, public_key: bytes, challenge: str) -> str:
        return _challenge_response(public_key + b"." + self._endpoint_id.encode(), challenge, "v2a")
