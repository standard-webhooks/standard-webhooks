package standardwebhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type webhookSymmetric struct {
	key []byte
}

func NewWebhookSymmetric(secret string) (Webhook, error) {
	key, err := base64enc.DecodeString(strings.TrimPrefix(secret, webhookSymmetricSecretPrefix))
	if err != nil {
		return nil, fmt.Errorf("unable to create webhook, err: %w", err)
	}
	return &webhookSymmetric{
		key: key,
	}, nil
}

func NewWebhookSymmetricRaw(secret []byte) (*webhookSymmetric, error) {
	return &webhookSymmetric{
		key: secret,
	}, nil
}

// Verify validates the payload against the webhook signature headers
// using the webhooks signing secret.
//
// Returns an error if the body or headers are missing/unreadable
// or if the signature doesn't match.
func (wh *webhookSymmetric) Verify(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, true)
}

// VerifyIgnoringTimestamp validates the payload against the webhook signature headers
// using the webhooks signing secret.
//
// Returns an error if the body or headers are missing/unreadable
// or if the signature doesn't match.
//
// WARNING: This function does not check the signature's timestamp.
// We recommend using the `Verify` function instead.
func (wh *webhookSymmetric) VerifyIgnoringTimestamp(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, false)
}

func (wh *webhookSymmetric) verify(payload []byte, headers http.Header, enforceTolerance bool) error {
	msgId, msgSignature, timestamp, err := checkHeaders(headers, enforceTolerance)
	if err != nil {
		return err
	}

	_, expectedSignature, err := wh.sign(msgId, timestamp, payload)
	if err != nil {
		return fmt.Errorf("unable to verify payload, err: %w", err)
	}

	err = matchSignature(msgSignature, "v1", func(signature []byte) bool {
		return hmac.Equal(signature, expectedSignature)
	})
	if err != nil {
		return fmt.Errorf("unable to verify payload, err: %w", ErrNoMatchingSignature)
	}
	return nil
}

func (wh *webhookSymmetric) Sign(msgId string, timestamp time.Time, payload []byte) (string, error) {
	version, signature, err := wh.sign(msgId, timestamp, payload)
	return signatureFormat(version, signature), err
}

func (wh *webhookSymmetric) sign(msgId string, timestamp time.Time, payload []byte) (version string, signature []byte, err error) {
	toSign := payloadToSign(msgId, timestamp, payload)

	h := hmac.New(sha256.New, wh.key)
	h.Write([]byte(toSign))
	sig := make([]byte, base64enc.EncodedLen(h.Size()))
	base64enc.Encode(sig, h.Sum(nil))

	return "v1", sig, nil
}

func parseTimestampHeader(timestampHeader string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to parse timestamp header, err: %w", errors.Join(err, ErrInvalidHeaders))
	}
	timestamp := time.Unix(timeInt, 0)
	return timestamp, nil
}

func verifyTimestamp(timestamp time.Time) error {
	now := time.Now()

	if now.Sub(timestamp) > tolerance {
		return ErrMessageTooOld
	}

	if timestamp.After(now.Add(tolerance)) {
		return ErrMessageTooNew
	}

	return nil
}
