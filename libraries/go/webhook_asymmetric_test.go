package standardwebhooks_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

var defaultAsymmetricPrivate = "V0VCSE9PS0FTWU1NRVRSSUNURVNUUFJJVkFURUtFWTE="

func newAsymmetricTestPayload(timestamp time.Time) (*testPayload, error) {
	tp := &testPayload{}
	tp.id = defaultMsgID
	tp.timestamp = timestamp

	tp.payload = defaultPayload
	tp.secret = defaultAsymmetricPrivate

	wh, err := standardwebhooks.NewWebhookAsymmetric(nil, &tp.secret)
	if err != nil {
		return nil, err
	}
	tp.signature, err = wh.Sign(tp.id, tp.timestamp, tp.payload)
	if err != nil {
		return nil, err
	}

	tp.header = http.Header{}
	tp.header.Set(standardwebhooks.HeaderWebhookID, tp.id)
	tp.header.Set(standardwebhooks.HeaderWebhookSignature, tp.signature)
	tp.header.Set(standardwebhooks.HeaderWebhookTimestamp, fmt.Sprint(tp.timestamp.Unix()))

	return tp, nil
}

func TestAsymmetricWebhook(t *testing.T) {

	testCases := []struct {
		name               string
		testPayloadTime    time.Time
		modifyPayload      func(*testPayload)
		noEnforceTimestamp bool
		expectedErr        bool
	}{
		{
			name:            "valid signature is valid",
			testPayloadTime: time.Now(),
			expectedErr:     false,
		},
		{
			name:            "missing id returns error",
			testPayloadTime: time.Now(),
			modifyPayload: func(tp *testPayload) {
				tp.header.Del("webhook-id")
			},
			expectedErr: true,
		},
		{
			name:            "missing timestamp returns error",
			testPayloadTime: time.Now(),
			modifyPayload: func(tp *testPayload) {
				tp.header.Del("webhook-timestamp")
			},
			expectedErr: true,
		},
		{
			name:            "missing signature returns error",
			testPayloadTime: time.Now(),
			modifyPayload: func(tp *testPayload) {
				tp.header.Del("webhook-signature")
			},
			expectedErr: true,
		},
		{
			name:            "invalid signature is invalid",
			testPayloadTime: time.Now(),
			modifyPayload: func(tp *testPayload) {
				tp.header.Set("webhook-signature", "v1a,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=")
			},
			expectedErr: true,
		},
		{
			name:            "partial signature is invalid",
			testPayloadTime: time.Now(),
			modifyPayload: func(tp *testPayload) {
				tp.header.Set("webhook-signature", "v1a,")
			},
			expectedErr: true,
		},
		{
			name:            "old timestamp fails",
			testPayloadTime: time.Now().Add(tolerance * -1),
			expectedErr:     true,
		},
		{
			name:            "new timestamp fails",
			testPayloadTime: time.Now().Add(tolerance + time.Second),
			expectedErr:     true,
		},
		{
			name:            "valid multi sig is valid",
			testPayloadTime: time.Now(),
			modifyPayload: func(tp *testPayload) {
				sigs := []string{
					"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
					"v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
					tp.header.Get("webhook-signature"), // valid signature
					"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
				}
				tp.header.Set("webhook-signature", strings.Join(sigs, " "))
			},
			expectedErr: false,
		},
		{
			name:               "old timestamp passes when ignoring tolerance",
			testPayloadTime:    time.Now().Add(tolerance * -1),
			noEnforceTimestamp: true,
			expectedErr:        false,
		},
		{
			name:               "new timestamp passes when ignoring tolerance",
			testPayloadTime:    time.Now().Add(tolerance * 1),
			noEnforceTimestamp: true,
			expectedErr:        false,
		},
		{
			name:               "valid timestamp passes when ignoring tolerance",
			testPayloadTime:    time.Now(),
			noEnforceTimestamp: true,
			expectedErr:        false,
		},
		{
			name:            "invalid timestamp fails when ignoring tolerance",
			testPayloadTime: time.Now(),
			modifyPayload: func(tp *testPayload) {
				tp.header.Set("webhook-timestamp", fmt.Sprint(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()))
			},
			noEnforceTimestamp: true,
			expectedErr:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testPayload, err := newAsymmetricTestPayload(tc.testPayloadTime)
			if err != nil {
				t.Fatal(err)
			}
			if tc.modifyPayload != nil {
				tc.modifyPayload(testPayload)
			}

			wh, err := standardwebhooks.NewWebhookAsymmetric(nil, &testPayload.secret)
			if err != nil {
				t.Fatal(err)
			}
			if tc.noEnforceTimestamp {
				err = wh.VerifyIgnoringTimestamp(testPayload.payload, testPayload.header)
			} else {
				err = wh.Verify(testPayload.payload, testPayload.header)
			}
			if err != nil && !tc.expectedErr {
				t.Errorf("%s: failed with err %s but shouldn't have", tc.name, err.Error())
			} else if err == nil && tc.expectedErr {
				t.Errorf("%s: didn't error but should have", tc.name)
			}
		})
	}
}

func TestAsymmetricWebhookPrefix(t *testing.T) {
	tp, err := newAsymmetricTestPayload(time.Now())
	if err != nil {
		t.Fatal(err)
	}

	wh, err := standardwebhooks.NewWebhookAsymmetric(nil, &tp.secret)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("SIG: \n%v\n", tp.header.Get(standardwebhooks.HeaderWebhookSignature))

	err = wh.Verify(tp.payload, tp.header)
	if err != nil {
		t.Fatal(err)
	}

	prefixedKey := fmt.Sprintf("whsk_%s", tp.secret)
	whPrefix, err := standardwebhooks.NewWebhookAsymmetric(nil, &prefixedKey)
	if err != nil {
		t.Fatal(err)
	}

	err = whPrefix.Verify(tp.payload, tp.header)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAsymmetricWebhookSign(t *testing.T) {
	key := "VEVTVFNJR05JTkdLRVlET05PVFVTRVRISVNGT1JBTlk="
	msgID := "msg_p5jXN8AQM9LWM0D4loKWxJek"
	timestamp := time.Unix(1614265330, 0)
	payload := []byte(`{"test": 2432232314}`)
	expected := "v1a,tQ9V2XOqn7jL/DQenEFpqIugdBVtiMmER5mhSkXBNwM0mkATuDe6KYYUuxqtaiHeYGb7KaaBRdM5WqyeFiL8Ag=="

	wh, err := standardwebhooks.NewWebhookAsymmetric(nil, &key)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := wh.Sign(msgID, timestamp, payload)
	if err != nil {
		t.Fatal(err)
	}

	if signature != expected {
		t.Fatalf("signature %s != expected signature %s", signature, expected)
	}
}
