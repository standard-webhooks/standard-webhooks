package standardwebhooks

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const (
	HeaderWebhookID        string = "webhook-id"
	HeaderWebhookSignature string = "webhook-signature"
	HeaderWebhookTimestamp string = "webhook-timestamp"

	webhookSecretPrefix string = "whsec_"
)

var (
	ErrRequiredHeaders     = errors.New("missing required headers")
	ErrInvalidHeaders      = errors.New("invalid signature headers")
	ErrNoMatchingSignature = errors.New("no matching signature found")
	ErrMessageTooOld       = errors.New("message timestamp too old")
	ErrMessageTooNew       = errors.New("message timestamp too new")
)

var base64enc = base64.StdEncoding

var tolerance time.Duration = 5 * time.Minute

type Webhook interface {
	Verify(payload []byte, headers http.Header) error
	VerifyIgnoringTimestamp(payload []byte, headers http.Header) error
	Sign(msgId string, timestamp time.Time, payload []byte) (string, error)
}
