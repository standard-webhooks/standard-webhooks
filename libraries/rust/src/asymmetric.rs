// SPDX-FileCopyrightText: © 2026 Standard Webhooks Authors
// SPDX-License-Identifier: MIT

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use http::HeaderMap;
use time::OffsetDateTime;

use crate::{parse_verify_headers, secure_compare, sign_challenge, WebhookError};

const PUBLIC_KEY_PREFIX: &str = "whpk_";
const SIGNATURE_VERSION: &str = "v2a";

/// Errors returned when creating a [`WebhookAsymmetric`]
///
/// Verification errors are returned as [`WebhookError`], same as with [`crate::Webhook`].
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum WebhookAsymmetricError {
    #[error("at least one public key is required")]
    NoPublicKeys,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("endpoint id may not be empty or contain '.'")]
    InvalidEndpointId,
}

/// Verifies webhooks signed with asymmetric (`v2a`) signatures
///
/// It only verifies signatures: producers are expected to sign webhooks using a private key held
/// in a KMS or an HSM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookAsymmetric {
    public_keys: Box<[VerifyingKey]>,
    endpoint_id: Box<str>,
}

impl WebhookAsymmetric {
    /// Create a verifier for asymmetric (`v2a`) signatures
    ///
    /// `endpoint_id` is the ID of the endpoint, as shared by the producer. It may not be empty or
    /// contain a `.`.
    ///
    /// `public_keys` is the list of trusted public keys, each serialized as `whpk_` followed by
    /// the base64 encoded ed25519 public key. A webhook is accepted if it was signed by any of
    /// them, so keys can be rotated by adding the new key to the list. The list should be ordered
    /// from newest to oldest: the first key is the one used for responding to endpoint
    /// verification challenges.
    pub fn new<S: AsRef<str>>(
        endpoint_id: &str,
        public_keys: &[S],
    ) -> Result<Self, WebhookAsymmetricError> {
        if public_keys.is_empty() {
            return Err(WebhookAsymmetricError::NoPublicKeys);
        }
        if endpoint_id.is_empty() || endpoint_id.contains('.') {
            return Err(WebhookAsymmetricError::InvalidEndpointId);
        }

        let public_keys = public_keys
            .iter()
            .map(|key| Self::parse_public_key(key.as_ref()))
            .collect::<Result<_, _>>()?;

        Ok(WebhookAsymmetric {
            public_keys,
            endpoint_id: endpoint_id.into(),
        })
    }

    fn parse_public_key(key: &str) -> Result<VerifyingKey, WebhookAsymmetricError> {
        let key = key
            .strip_prefix(PUBLIC_KEY_PREFIX)
            .ok_or(WebhookAsymmetricError::InvalidPublicKey)?;
        let key: [u8; PUBLIC_KEY_LENGTH] = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| WebhookAsymmetricError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| WebhookAsymmetricError::InvalidPublicKey)?;

        VerifyingKey::from_bytes(&key).map_err(|_| WebhookAsymmetricError::InvalidPublicKey)
    }

    /// Verify the webhook signature against payload and headers
    pub fn verify(&self, payload: &[u8], headers: &HeaderMap) -> Result<(), WebhookError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.verify_with_timestamp(payload, headers, now)
    }

    /// Similar to [Self::verify] but uses a timestamp passed as a parameter instead of `now()`
    pub fn verify_with_timestamp(
        &self,
        payload: &[u8],
        headers: &HeaderMap,
        now: i64,
    ) -> Result<(), WebhookError> {
        let (msg_id, msg_signature, msg_ts) = parse_verify_headers(headers, now)?;

        let mut hasher = hmac_sha256::Hash::new();
        hasher.update(format!("{}.{msg_id}.{msg_ts}.", self.endpoint_id));
        hasher.update(payload);
        let digest = hasher.finalize();

        msg_signature
            .split(' ')
            .filter_map(|x| x.strip_prefix(SIGNATURE_VERSION)?.strip_prefix(','))
            .filter_map(|x| {
                let signature: [u8; SIGNATURE_LENGTH] = base64::engine::general_purpose::STANDARD
                    .decode(x)
                    .ok()?
                    .try_into()
                    .ok()?;
                Some(Signature::from_bytes(&signature))
            })
            .any(|signature| {
                self.public_keys
                    .iter()
                    .any(|key| key.verify(&digest, &signature).is_ok())
            })
            .then_some(())
            .ok_or(WebhookError::InvalidSignature)
    }

    /// Calculate the response to an endpoint verification challenge
    ///
    /// Takes the value of the `webhook-challenge` header and returns the value for the
    /// `webhook-challenge-response` header. The response is calculated using the first (newest)
    /// public key.
    pub fn endpoint_verification_response(&self, challenge: &str) -> String {
        self.endpoint_verification_response_for_key(&self.public_keys[0], challenge)
    }

    /// Verify the value of the `webhook-challenge-response` header against the challenge sent
    ///
    /// The response is accepted if it was calculated using any of the public keys.
    pub fn verify_endpoint_verification_response(
        &self,
        challenge: &str,
        header: &str,
    ) -> Result<(), WebhookError> {
        self.public_keys
            .iter()
            .any(|key| {
                secure_compare(
                    header,
                    &self.endpoint_verification_response_for_key(key, challenge),
                )
            })
            .then_some(())
            .ok_or(WebhookError::InvalidSignature)
    }

    fn endpoint_verification_response_for_key(
        &self,
        key: &VerifyingKey,
        challenge: &str,
    ) -> String {
        let endpoint_key = [key.as_bytes().as_slice(), b".", self.endpoint_id.as_bytes()].concat();
        let encoded = sign_challenge(&endpoint_key, challenge);

        format!("{SIGNATURE_VERSION},{encoded}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HEADER_WEBHOOK_ID, HEADER_WEBHOOK_SIGNATURE, HEADER_WEBHOOK_TIMESTAMP, TOLERANCE_IN_SECONDS,
    };
    use ed25519_dalek::{Signer, SigningKey};

    // Test-only keys from the spec. Never use them for anything else.
    const SECRET_KEY: &str = "whsk_4uKPjji/dhB8w6GW3YYDnIMYvXcdHrvH6lidTr4Z+EY=";
    const PUBLIC_KEY: &str = "whpk_uWKK13PfwqyOgrqT0OrWKcS2uVD7e89+oUKnkoPjx7w=";
    const ENDPOINT_ID: &str = "ep_2fVZdC8Kx9TR4ZoCqHWt3NnLgRb";
    // An unrelated key, used for testing key lists
    const OTHER_SECRET_KEY: &str = "whsk_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwMfKQ9r8GKYo=";

    const MSG_ID: &str = "msg_27UH4WbU6Z5A5EzD8u03UvzRbpk";
    const PAYLOAD: &[u8] = br#"{"email":"test@example.com","username":"test_user"}"#;

    const CHALLENGE: &str = "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM=";
    const CHALLENGE_RESPONSE: &str = "v2a,t0RDFhzk7OtVzgvMsjuXnodSWuby2BVX+zPqw2/ksUk=";

    fn signing_key(secret_key: &str) -> SigningKey {
        let seed: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(secret_key.strip_prefix("whsk_").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn public_key(signing_key: &SigningKey) -> String {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().as_bytes());
        format!("whpk_{encoded}")
    }

    fn sign(
        signing_key: &SigningKey,
        endpoint_id: &str,
        msg_id: &str,
        timestamp: i64,
        payload: &[u8],
    ) -> String {
        let mut content = format!("{endpoint_id}.{msg_id}.{timestamp}.").into_bytes();
        content.extend_from_slice(payload);
        let digest = hmac_sha256::Hash::hash(&content);
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(signing_key.sign(&digest).to_bytes());
        format!("v2a,{encoded}")
    }

    fn headers(msg_id: &str, signature: &str, timestamp: i64) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_WEBHOOK_ID, msg_id.parse().unwrap());
        headers.insert(HEADER_WEBHOOK_SIGNATURE, signature.parse().unwrap());
        headers.insert(
            HEADER_WEBHOOK_TIMESTAMP,
            timestamp.to_string().parse().unwrap(),
        );
        headers
    }

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn test_spec_vector() {
        let msg_id = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W";
        let timestamp = 1674087231;
        let payload = br#"{"type":"contact.created","timestamp":"2022-11-03T20:26:10.344522Z","data":{"id":"1f81eb52-5198-4599-803e-771906343485"}}"#;
        let signature = "v2a,kG9XaxZjAEpKB8KeQQb5G1Xp73YH5Rf5gxoWe7cg1kYMiyspdtZXe9w+dAwKeOurAwxfqmlOG/QR4m9s37DzAg==";

        let key = signing_key(SECRET_KEY);
        assert_eq!(public_key(&key), PUBLIC_KEY);

        let mut content = format!("{ENDPOINT_ID}.{msg_id}.{timestamp}.").into_bytes();
        content.extend_from_slice(payload);
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(hmac_sha256::Hash::hash(&content)),
            "YXCi5iN+rjB+iEb6bvg1XbWbVBL+r2S+as3k3n1Ih/A="
        );
        assert_eq!(
            sign(&key, ENDPOINT_ID, msg_id, timestamp, payload),
            signature
        );

        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY]).unwrap();
        let headers = headers(msg_id, signature, timestamp);
        wh.verify_with_timestamp(payload, &headers, timestamp)
            .unwrap();
        assert_eq!(
            wh.verify(payload, &headers),
            Err(WebhookError::TimestampTooOldError)
        );
    }

    #[test]
    fn test_verify() {
        let key = signing_key(SECRET_KEY);
        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY]).unwrap();

        let ts = now();
        let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, PAYLOAD);
        wh.verify(PAYLOAD, &headers(MSG_ID, &signature, ts))
            .unwrap();
    }

    #[test]
    fn test_verify_binary_payload() {
        let key = signing_key(SECRET_KEY);
        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY]).unwrap();

        let payload = b"\xff\x00\xfe binary";
        let ts = now();
        let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, payload);
        wh.verify(payload, &headers(MSG_ID, &signature, ts))
            .unwrap();
    }

    #[test]
    fn test_verify_with_other_signatures() {
        let key = signing_key(SECRET_KEY);
        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY]).unwrap();

        let ts = now();
        let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, PAYLOAD);

        let multi_sig = format!("v1,tFtCZ5RDCPxzWQRWXWPgrCgE2frDBe9gjpbWQxnVfsQ= {signature}");
        wh.verify(PAYLOAD, &headers(MSG_ID, &multi_sig, ts))
            .unwrap();

        let malformed = format!(",,, v2a v2a,not-base64 v2a,AAAA v1a,abc  {signature}");
        wh.verify(PAYLOAD, &headers(MSG_ID, &malformed, ts))
            .unwrap();

        // A valid signature with another version
        let other_version = signature.replacen("v2a,", "v1a,", 1);
        assert_eq!(
            wh.verify(PAYLOAD, &headers(MSG_ID, &other_version, ts)),
            Err(WebhookError::InvalidSignature)
        );
    }

    #[test]
    fn test_verify_key_rotation() {
        let key = signing_key(SECRET_KEY);
        let other_public_key = public_key(&signing_key(OTHER_SECRET_KEY));

        let ts = now();
        let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, PAYLOAD);
        let headers = headers(MSG_ID, &signature, ts);

        // Signed by the second key in the list
        let wh =
            WebhookAsymmetric::new(ENDPOINT_ID, &[other_public_key.as_str(), PUBLIC_KEY]).unwrap();
        wh.verify(PAYLOAD, &headers).unwrap();

        // Signed by a key that isn't in the list
        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[other_public_key]).unwrap();
        assert_eq!(
            wh.verify(PAYLOAD, &headers),
            Err(WebhookError::InvalidSignature)
        );
    }

    #[test]
    fn test_no_verify_wrong_endpoint_id() {
        let key = signing_key(SECRET_KEY);
        let wh = WebhookAsymmetric::new("ep_other", &[PUBLIC_KEY]).unwrap();

        let ts = now();
        let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, PAYLOAD);
        assert_eq!(
            wh.verify(PAYLOAD, &headers(MSG_ID, &signature, ts)),
            Err(WebhookError::InvalidSignature)
        );
    }

    #[test]
    fn test_no_verify_tampered_payload() {
        let key = signing_key(SECRET_KEY);
        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY]).unwrap();

        let ts = now();
        let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, PAYLOAD);
        assert_eq!(
            wh.verify(
                br#"{"email":"test@example.com","username":"test_user2"}"#,
                &headers(MSG_ID, &signature, ts)
            ),
            Err(WebhookError::InvalidSignature)
        );
    }

    #[test]
    fn test_verify_incorrect_timestamp() {
        let key = signing_key(SECRET_KEY);
        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY]).unwrap();

        for (ts, err) in [
            (
                now() - (TOLERANCE_IN_SECONDS + 1),
                WebhookError::TimestampTooOldError,
            ),
            (
                now() + (TOLERANCE_IN_SECONDS + 1),
                WebhookError::FutureTimestampError,
            ),
        ] {
            let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, PAYLOAD);
            assert_eq!(
                wh.verify(PAYLOAD, &headers(MSG_ID, &signature, ts)),
                Err(err)
            );
        }
    }

    #[test]
    fn test_missing_headers() {
        let key = signing_key(SECRET_KEY);
        let wh = WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY]).unwrap();

        let ts = now();
        let signature = sign(&key, ENDPOINT_ID, MSG_ID, ts, PAYLOAD);
        for (hdr, name) in [
            (HEADER_WEBHOOK_ID, "id"),
            (HEADER_WEBHOOK_SIGNATURE, "signature"),
            (HEADER_WEBHOOK_TIMESTAMP, "timestamp"),
        ] {
            let mut headers = headers(MSG_ID, &signature, ts);
            headers.remove(hdr);
            assert_eq!(
                wh.verify(PAYLOAD, &headers),
                Err(WebhookError::MissingHeader(name))
            );
        }
    }

    #[test]
    fn test_constructor_errors() {
        let no_keys: [&str; 0] = [];
        let unprefixed = PUBLIC_KEY.strip_prefix("whpk_").unwrap();
        let whsec = format!("whsec_{unprefixed}");
        for (keys, endpoint_id, err) in [
            (
                &no_keys[..],
                ENDPOINT_ID,
                WebhookAsymmetricError::NoPublicKeys,
            ),
            (
                &[unprefixed][..],
                ENDPOINT_ID,
                WebhookAsymmetricError::InvalidPublicKey,
            ),
            (
                &[whsec.as_str()][..],
                ENDPOINT_ID,
                WebhookAsymmetricError::InvalidPublicKey,
            ),
            (
                &["whpk_not base64!"][..],
                ENDPOINT_ID,
                WebhookAsymmetricError::InvalidPublicKey,
            ),
            (
                &["whpk_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"][..],
                ENDPOINT_ID,
                WebhookAsymmetricError::InvalidPublicKey,
            ),
            (
                &["whpk_"][..],
                ENDPOINT_ID,
                WebhookAsymmetricError::InvalidPublicKey,
            ),
            (
                &[PUBLIC_KEY, "whpk_"][..],
                ENDPOINT_ID,
                WebhookAsymmetricError::InvalidPublicKey,
            ),
            (
                &[PUBLIC_KEY][..],
                "",
                WebhookAsymmetricError::InvalidEndpointId,
            ),
            (
                &[PUBLIC_KEY][..],
                "ep_abc.def",
                WebhookAsymmetricError::InvalidEndpointId,
            ),
        ] {
            assert_eq!(WebhookAsymmetric::new(endpoint_id, keys), Err(err));
        }
    }

    #[test]
    fn test_challenge_response() {
        let other_public_key = public_key(&signing_key(OTHER_SECRET_KEY));
        let wh =
            WebhookAsymmetric::new(ENDPOINT_ID, &[PUBLIC_KEY, other_public_key.as_str()]).unwrap();
        assert_eq!(
            CHALLENGE_RESPONSE.to_owned(),
            wh.endpoint_verification_response(CHALLENGE)
        );
    }

    #[test]
    fn test_verify_challenge_response() {
        let other_public_key = public_key(&signing_key(OTHER_SECRET_KEY));
        // The matching key is the second one in the list
        let wh =
            WebhookAsymmetric::new(ENDPOINT_ID, &[other_public_key.as_str(), PUBLIC_KEY]).unwrap();

        wh.verify_endpoint_verification_response(CHALLENGE, CHALLENGE_RESPONSE)
            .unwrap();
        assert_eq!(
            Err(WebhookError::InvalidSignature),
            wh.verify_endpoint_verification_response(
                CHALLENGE,
                &format!("v2,abc {CHALLENGE_RESPONSE}")
            )
        );
        assert_eq!(
            Err(WebhookError::InvalidSignature),
            wh.verify_endpoint_verification_response("wrong-challenge", CHALLENGE_RESPONSE)
        );

        let wh = WebhookAsymmetric::new("ep_other", &[PUBLIC_KEY]).unwrap();
        assert_eq!(
            Err(WebhookError::InvalidSignature),
            wh.verify_endpoint_verification_response(CHALLENGE, CHALLENGE_RESPONSE)
        );
    }
}
