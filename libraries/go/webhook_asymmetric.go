package standardwebhooks

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	webhookPublicKeyPrefix     string = "whpk_"
	asymmetricSignatureVersion string = "v2a"
)

var (
	ErrNoPublicKeys      = errors.New("at least one public key is required")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidEndpointID = errors.New("endpoint id may not be empty or contain '.'")
)

// WebhookAsymmetric verifies webhooks signed with asymmetric (`v2a`) signatures.
//
// It only verifies signatures: producers are expected to sign webhooks using
// a private key held in a KMS or an HSM.
type WebhookAsymmetric struct {
	publicKeys []ed25519.PublicKey
	endpointID string
}

// NewWebhookAsymmetric creates a verifier for asymmetric (`v2a`) signatures.
//
// endpointID is the ID of the endpoint, as shared by the producer. It may not
// be empty or contain a `.`.
//
// publicKeys is the list of trusted public keys, each serialized as `whpk_` followed
// by the base64 encoded ed25519 public key. A webhook is accepted if it was signed
// by any of them, so keys can be rotated by adding the new key to the list.
// The list should be ordered from newest to oldest: the first key is the one
// used for responding to endpoint verification challenges.
func NewWebhookAsymmetric(endpointID string, publicKeys []string) (*WebhookAsymmetric, error) {
	if len(publicKeys) == 0 {
		return nil, ErrNoPublicKeys
	}
	if endpointID == "" || strings.Contains(endpointID, ".") {
		return nil, ErrInvalidEndpointID
	}

	keys := make([]ed25519.PublicKey, 0, len(publicKeys))
	for _, publicKey := range publicKeys {
		encoded, ok := strings.CutPrefix(publicKey, webhookPublicKeyPrefix)
		if !ok {
			return nil, fmt.Errorf("unable to create webhook, err: %w", ErrInvalidPublicKey)
		}
		key, err := base64enc.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("unable to create webhook, err: %w", errors.Join(err, ErrInvalidPublicKey))
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("unable to create webhook, err: %w", ErrInvalidPublicKey)
		}
		keys = append(keys, ed25519.PublicKey(key))
	}

	return &WebhookAsymmetric{
		publicKeys: keys,
		endpointID: endpointID,
	}, nil
}

// Verify validates the payload against the webhook signature headers
// using the trusted public keys and the endpoint ID.
//
// Returns an error if the body or headers are missing/unreadable
// or if no signature matches.
func (wh *WebhookAsymmetric) Verify(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, true)
}

// VerifyIgnoringTimestamp validates the payload against the webhook signature headers
// using the trusted public keys and the endpoint ID.
//
// Returns an error if the body or headers are missing/unreadable
// or if no signature matches.
//
// WARNING: This function does not check the signature's timestamp.
// We recommend using the `Verify` function instead.
func (wh *WebhookAsymmetric) VerifyIgnoringTimestamp(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, false)
}

func (wh *WebhookAsymmetric) verify(payload []byte, headers http.Header, enforceTolerance bool) error {
	msgId, msgSignature, timestamp, err := parseVerifyHeaders(headers, enforceTolerance)
	if err != nil {
		return err
	}

	content := append([]byte(fmt.Sprintf("%s.%s.%d.", wh.endpointID, msgId, timestamp.Unix())), payload...)
	digest := sha256.Sum256(content)

	prefix := asymmetricSignatureVersion + ","
	for _, versionedSignature := range strings.Split(msgSignature, " ") {
		encoded, ok := strings.CutPrefix(versionedSignature, prefix)
		if !ok {
			continue
		}
		signature, err := base64enc.DecodeString(encoded)
		if err != nil || len(signature) != ed25519.SignatureSize {
			continue
		}
		for _, publicKey := range wh.publicKeys {
			if ed25519.Verify(publicKey, digest[:], signature) {
				return nil
			}
		}
	}

	return fmt.Errorf("unable to verify payload, err: %w", ErrNoMatchingSignature)
}

// EndpointVerificationResponse calculates the response to an endpoint verification challenge.
//
// Takes the value of the `webhook-challenge` header and returns the value
// for the `webhook-challenge-response` header. The response is calculated
// using the first (newest) public key.
func (wh *WebhookAsymmetric) EndpointVerificationResponse(challenge string) string {
	return wh.endpointVerificationResponse(wh.publicKeys[0], challenge)
}

// VerifyEndpointVerificationResponse validates the value of the `webhook-challenge-response`
// header against the challenge that was sent.
//
// The response is accepted if it was calculated using any of the public keys.
// Returns an error if the signature doesn't match.
func (wh *WebhookAsymmetric) VerifyEndpointVerificationResponse(challenge string, header string) error {
	for _, publicKey := range wh.publicKeys {
		if hmac.Equal([]byte(header), []byte(wh.endpointVerificationResponse(publicKey, challenge))) {
			return nil
		}
	}

	return fmt.Errorf("unable to verify challenge response, err: %w", ErrNoMatchingSignature)
}

func (wh *WebhookAsymmetric) endpointVerificationResponse(publicKey ed25519.PublicKey, challenge string) string {
	endpointKey := make([]byte, 0, len(publicKey)+1+len(wh.endpointID))
	endpointKey = append(endpointKey, publicKey...)
	endpointKey = append(endpointKey, '.')
	endpointKey = append(endpointKey, wh.endpointID...)

	return fmt.Sprintf("%s,%s", asymmetricSignatureVersion, signChallenge(endpointKey, challenge))
}
