package standardwebhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderWebhookID        string = "webhook-id"
	HeaderWebhookSignature string = "webhook-signature"
	HeaderWebhookTimestamp string = "webhook-timestamp"

	webhookSecretPrefix string = "whsec_"
)

var base64enc = base64.StdEncoding

var tolerance time.Duration = 5 * time.Minute

var (
	errRequiredHeaders     = errors.New("missing required headers")
	errInvalidHeaders      = errors.New("invalid signature headers")
	errNoMatchingSignature = errors.New("no matching signature found")
	errMessageTooOld       = errors.New("message timestamp too old")
	errMessageTooNew       = errors.New("message timestamp too new")
)

type Webhook struct {
	key []byte
}

func NewWebhook(secret string) (*Webhook, error) {
	key, err := base64enc.DecodeString(strings.TrimPrefix(secret, webhookSecretPrefix))
	if err != nil {
		return nil, err
	}
	return &Webhook{
		key: key,
	}, nil
}

func NewWebhookRaw(secret []byte) (*Webhook, error) {
	return &Webhook{
		key: secret,
	}, nil
}

// Verify validates the payload against the webhook signature headers
// using the webhooks signing secret.
//
// Returns an error if the body or headers are missing/unreadable
// or if the signature doesn't match.
func (wh *Webhook) Verify(payload []byte, headers http.Header) error {
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
func (wh *Webhook) VerifyIgnoringTimestamp(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, false)
}

func (wh *Webhook) verify(payload []byte, headers http.Header, enforceTolerance bool) error {
	msgId := headers.Get(HeaderWebhookID)
	msgSignature := headers.Get(HeaderWebhookSignature)
	msgTimestamp := headers.Get(HeaderWebhookTimestamp)
	if msgId == "" || msgSignature == "" || msgTimestamp == "" {
		return errRequiredHeaders
	}

	timestamp, err := parseTimestampHeader(msgTimestamp)
	if err != nil {
		return err
	}

	if enforceTolerance {
		if err := verifyTimestamp(timestamp); err != nil {
			return err
		}
	}

	computedSignature, err := wh.Sign(msgId, timestamp, payload)
	if err != nil {
		return err
	}
	expectedSignature := []byte(strings.Split(computedSignature, ",")[1])

	passedSignatures := strings.Split(msgSignature, " ")
	for _, versionedSignature := range passedSignatures {
		sigParts := strings.Split(versionedSignature, ",")
		if len(sigParts) < 2 {
			continue
		}
		version := sigParts[0]
		signature := []byte(sigParts[1])

		if version != "v1" {
			continue
		}

		if hmac.Equal(signature, expectedSignature) {
			return nil
		}
	}
	return errNoMatchingSignature
}

func (wh *Webhook) Sign(msgId string, timestamp time.Time, payload []byte) (string, error) {
	toSign := fmt.Sprintf("%s.%d.%s", msgId, timestamp.Unix(), payload)

	h := hmac.New(sha256.New, wh.key)
	h.Write([]byte(toSign))
	sig := make([]byte, base64enc.EncodedLen(h.Size()))
	base64enc.Encode(sig, h.Sum(nil))
	return fmt.Sprintf("v1,%s", sig), nil

}

func parseTimestampHeader(timestampHeader string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return time.Time{}, errInvalidHeaders
	}
	timestamp := time.Unix(timeInt, 0)
	return timestamp, nil
}

func verifyTimestamp(timestamp time.Time) error {
	now := time.Now()

	if now.Sub(timestamp) > tolerance {
		return errMessageTooOld
	}
	if timestamp.Unix() > now.Add(tolerance).Unix() {
		return errMessageTooNew
	}

	return nil
}
