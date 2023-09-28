package standardwebhooks_test

import (
	"fmt"
	"log"
	"net/http"
	"time"

	standardwebhooks "github.com/standard-webhooks/libraries/go"
)

const (
	secretKey = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
)

// Example_signatureFlow describes the full flow of signature and verification
// of a webhook payload by verifying the timestamp also.
func Example_signatureFlow() {
	var (
		ts = time.Now().Format(time.RFC3339)
		id = "1234567890"
	)

	wh, err := standardwebhooks.NewWebhook(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	payload := fmt.Sprintf(`{"type": "example.created", "timestamp":"%s", "data":{"foo":"bar"}}`, ts)

	// signing the payload with the webhook handler
	signature, err := wh.Sign(id, time.Now(), []byte(payload))
	if err != nil {
		log.Fatal(err)
	}

	// Signature has been properly generated
	fmt.Println(signature)

	// generating the http header carrier
	header := http.Header{}
	header.Set("webhook-id", id)
	header.Set("webhook-signature", signature)
	header.Set("webhook-timestamp", ts)

	// http request is sent to consumer

	// consumer verifies the signature
	err = wh.Verify([]byte(payload), header)
	if err != nil {
		log.Fatal(err)
	}
}
