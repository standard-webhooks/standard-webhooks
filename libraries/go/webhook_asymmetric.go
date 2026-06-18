package standardwebhooks

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type webhookAsymmetric struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewWebhookAsymmetric(publicKey *string, privateKey *string) (Webhook, error) {
	if publicKey == nil && privateKey == nil {
		return nil, ErrMissingKeys
	}
	wh := &webhookAsymmetric{}
	if publicKey != nil {
		pubkey, err := base64enc.DecodeString(strings.TrimPrefix(*publicKey, webhookAsymmetricPublicPrefix))
		if err != nil {
			return nil, fmt.Errorf("unable to create webhook, err: %w", err)
		}
		wh.publicKey = ed25519.PublicKey(pubkey)
	}
	if privateKey != nil {
		privKey, err := base64enc.DecodeString(strings.TrimPrefix(*privateKey, webhookAsymmetricPrivatePrefix))
		if err != nil {
			return nil, fmt.Errorf("unable to create webhook, err: %w", err)
		}
		wh.privateKey = ed25519.NewKeyFromSeed(privKey)
		if wh.publicKey == nil {
			wh.publicKey = wh.privateKey.Public().(ed25519.PublicKey)
		}
	}

	return wh, nil
}

func (wh *webhookAsymmetric) Sign(msgId string, timestamp time.Time, payload []byte) (string, error) {
	if wh.privateKey == nil {
		return "", ErrMissingPrivateKey
	}
	toSign := payloadToSign(msgId, timestamp, payload)
	signature := ed25519.Sign(wh.privateKey, []byte(toSign))
	b64Sig := make([]byte, base64enc.EncodedLen(len(signature)))
	base64enc.Encode(b64Sig, signature)
	return signatureFormat("v1a", b64Sig), nil
}

func (wh *webhookAsymmetric) Verify(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, true)
}

func (wh *webhookAsymmetric) VerifyIgnoringTimestamp(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, false)
}

func (wh *webhookAsymmetric) verify(payload []byte, headers http.Header, enforceTolerance bool) error {
	msgId, msgSignature, timestamp, err := checkHeaders(headers, enforceTolerance)
	if err != nil {
		return err
	}
	err = matchSignature(msgSignature, "v1a", func(b64Signature []byte) bool {
		signature := make([]byte, base64enc.DecodedLen(len(b64Signature)))
		n, err := base64enc.Decode(signature, b64Signature)
		if err != nil {
			return false
		}
		// decode will occasionally make too large of an array, remove any unwritten bytes from the signature
		signature = signature[:n]
		signedPayload := payloadToSign(msgId, timestamp, payload)
		return ed25519.Verify(wh.publicKey, []byte(signedPayload), signature)
	})
	if err != nil {
		return err
	}
	return nil
}
