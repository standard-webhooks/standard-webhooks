package standardwebhooks

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	HeaderWebhookID        string = "webhook-id"
	HeaderWebhookSignature string = "webhook-signature"
	HeaderWebhookTimestamp string = "webhook-timestamp"

	webhookSymmetricSecretPrefix   string = "whsec_"
	webhookAsymmetricPrivatePrefix string = "whsk_"
	webhookAsymmetricPublicPrefix  string = "whpk_"
)

var (
	ErrRequiredHeaders     = errors.New("missing required headers")
	ErrInvalidHeaders      = errors.New("invalid signature headers")
	ErrNoMatchingSignature = errors.New("no matching signature found")
	ErrMessageTooOld       = errors.New("message timestamp too old")
	ErrMessageTooNew       = errors.New("message timestamp too new")
	ErrMissingPrivateKey   = errors.New("missing private key")
	ErrMissingKeys         = errors.New("missing private or public key")
)

var base64enc = base64.StdEncoding

var tolerance time.Duration = 5 * time.Minute

type Webhook interface {
	Verify(payload []byte, headers http.Header) error
	VerifyIgnoringTimestamp(payload []byte, headers http.Header) error
	Sign(msgId string, timestamp time.Time, payload []byte) (string, error)
}

func payloadToSign(msgId string, timestamp time.Time, payload []byte) string {
	return fmt.Sprintf("%s.%d.%s", msgId, timestamp.Unix(), payload)
}

func signatureFormat(version string, signature []byte) string {
	return fmt.Sprintf("%s,%s", version, signature)
}

func checkHeaders(headers http.Header, enforceTolerance bool) (msgId string, msgSignature string, timestamp time.Time, err error) {
	msgId = headers.Get(HeaderWebhookID)
	msgSignature = headers.Get(HeaderWebhookSignature)
	msgTimestamp := headers.Get(HeaderWebhookTimestamp)

	if msgId == "" || msgSignature == "" || msgTimestamp == "" {
		err = fmt.Errorf("unable to verify payload, err: %w", ErrRequiredHeaders)
		return
	}

	timestamp, err = parseTimestampHeader(msgTimestamp)
	if err != nil {
		err = fmt.Errorf("unable to verify payload, err: %w", err)
		return
	}

	if enforceTolerance {
		if err = verifyTimestamp(timestamp); err != nil {
			err = fmt.Errorf("unable to verify payload, err: %w", err)
			return
		}
	}
	return
}

func matchSignature(msgSignature string, expectedVersion string, checkFunc func([]byte) bool) error {
	passedSignatures := strings.Split(msgSignature, " ")
	for _, versionedSignature := range passedSignatures {
		sigParts := strings.Split(versionedSignature, ",")
		if len(sigParts) < 2 {
			continue
		}

		version := sigParts[0]

		if version != expectedVersion {
			continue
		}

		signature := []byte(sigParts[1])
		if checkFunc(signature) {
			return nil
		}

	}
	return fmt.Errorf("unable to verify payload, err: %w", ErrNoMatchingSignature)
}
