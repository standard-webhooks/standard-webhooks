package standardwebhooks_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

// Test-only keys from the spec. Never use them for anything else.
const (
	asymmetricSecretKey  = "whsk_4uKPjji/dhB8w6GW3YYDnIMYvXcdHrvH6lidTr4Z+EY="
	asymmetricPublicKey  = "whpk_uWKK13PfwqyOgrqT0OrWKcS2uVD7e89+oUKnkoPjx7w="
	asymmetricEndpointID = "ep_2fVZdC8Kx9TR4ZoCqHWt3NnLgRb"
	// An unrelated key, used for testing key lists
	asymmetricOtherSecretKey = "whsk_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwMfKQ9r8GKYo="
)

func asymmetricPrivateKey(t *testing.T, secretKey string) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secretKey, "whsk_"))
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func asymmetricPublicKeyString(privateKey ed25519.PrivateKey) string {
	return "whpk_" + base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

func asymmetricSign(privateKey ed25519.PrivateKey, endpointID string, msgID string, timestamp time.Time, payload []byte) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s.%s.%d.%s", endpointID, msgID, timestamp.Unix(), payload)))
	return "v2a," + base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:]))
}

func asymmetricHeaders(msgID string, signature string, timestamp time.Time) http.Header {
	header := http.Header{}
	header.Set(standardwebhooks.HeaderWebhookID, msgID)
	header.Set(standardwebhooks.HeaderWebhookSignature, signature)
	header.Set(standardwebhooks.HeaderWebhookTimestamp, fmt.Sprint(timestamp.Unix()))
	return header
}

func TestWebhookAsymmetricSpecVector(t *testing.T) {
	msgID := "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W"
	timestamp := time.Unix(1674087231, 0)
	payload := []byte(`{"type":"contact.created","timestamp":"2022-11-03T20:26:10.344522Z","data":{"id":"1f81eb52-5198-4599-803e-771906343485"}}`)
	signature := "v2a,kG9XaxZjAEpKB8KeQQb5G1Xp73YH5Rf5gxoWe7cg1kYMiyspdtZXe9w+dAwKeOurAwxfqmlOG/QR4m9s37DzAg=="

	privateKey := asymmetricPrivateKey(t, asymmetricSecretKey)
	if pk := asymmetricPublicKeyString(privateKey); pk != asymmetricPublicKey {
		t.Fatalf("public key %s != expected public key %s", pk, asymmetricPublicKey)
	}

	digest := sha256.Sum256([]byte(fmt.Sprintf("%s.%s.%d.%s", asymmetricEndpointID, msgID, timestamp.Unix(), payload)))
	if d := base64.StdEncoding.EncodeToString(digest[:]); d != "YXCi5iN+rjB+iEb6bvg1XbWbVBL+r2S+as3k3n1Ih/A=" {
		t.Fatalf("unexpected digest %s", d)
	}

	if s := asymmetricSign(privateKey, asymmetricEndpointID, msgID, timestamp, payload); s != signature {
		t.Fatalf("signature %s != expected signature %s", s, signature)
	}

	wh, err := standardwebhooks.NewWebhookAsymmetric(asymmetricEndpointID, []string{asymmetricPublicKey})
	if err != nil {
		t.Fatal(err)
	}

	header := asymmetricHeaders(msgID, signature, timestamp)
	if err := wh.VerifyIgnoringTimestamp(payload, header); err != nil {
		t.Fatalf("expected spec vector to verify, got %s", err)
	}
	if err := wh.Verify(payload, header); !errors.Is(err, standardwebhooks.ErrMessageTooOld) {
		t.Fatalf("expected %s, got %v", standardwebhooks.ErrMessageTooOld, err)
	}
}

func TestWebhookAsymmetric(t *testing.T) {
	privateKey := asymmetricPrivateKey(t, asymmetricSecretKey)
	otherPrivateKey := asymmetricPrivateKey(t, asymmetricOtherSecretKey)
	otherPublicKey := asymmetricPublicKeyString(otherPrivateKey)

	testCases := []struct {
		name               string
		publicKeys         []string
		endpointID         string
		signingKey         ed25519.PrivateKey
		timestamp          time.Time
		modify             func(header http.Header, payload *[]byte)
		noEnforceTimestamp bool
		expectedErr        error
	}{
		{
			name:       "valid signature is valid",
			signingKey: privateKey,
		},
		{
			name:       "v1 entry followed by a valid signature is valid",
			signingKey: privateKey,
			modify: func(header http.Header, payload *[]byte) {
				header.Set("webhook-signature", "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= "+header.Get("webhook-signature"))
			},
		},
		{
			name:       "malformed entries followed by a valid signature is valid",
			signingKey: privateKey,
			modify: func(header http.Header, payload *[]byte) {
				header.Set("webhook-signature", ",,, v2a v2a,not-base64 v2a,AAAA v1a,abc  "+header.Get("webhook-signature"))
			},
		},
		{
			name:       "signature by the second key in the list is valid",
			publicKeys: []string{otherPublicKey, asymmetricPublicKey},
			signingKey: privateKey,
		},
		{
			name:        "signature by a key not in the list is invalid",
			publicKeys:  []string{otherPublicKey},
			signingKey:  privateKey,
			expectedErr: standardwebhooks.ErrNoMatchingSignature,
		},
		{
			name:        "wrong endpoint id is invalid",
			endpointID:  "ep_other",
			signingKey:  privateKey,
			expectedErr: standardwebhooks.ErrNoMatchingSignature,
		},
		{
			name:       "tampered payload is invalid",
			signingKey: privateKey,
			modify: func(header http.Header, payload *[]byte) {
				*payload = []byte(`{"test": 2432232315}`)
			},
			expectedErr: standardwebhooks.ErrNoMatchingSignature,
		},
		{
			name:       "valid signature with another version is invalid",
			signingKey: privateKey,
			modify: func(header http.Header, payload *[]byte) {
				header.Set("webhook-signature", strings.Replace(header.Get("webhook-signature"), "v2a,", "v1a,", 1))
			},
			expectedErr: standardwebhooks.ErrNoMatchingSignature,
		},
		{
			name:       "missing id returns error",
			signingKey: privateKey,
			modify: func(header http.Header, payload *[]byte) {
				header.Del("webhook-id")
			},
			expectedErr: standardwebhooks.ErrRequiredHeaders,
		},
		{
			name:       "missing timestamp returns error",
			signingKey: privateKey,
			modify: func(header http.Header, payload *[]byte) {
				header.Del("webhook-timestamp")
			},
			expectedErr: standardwebhooks.ErrRequiredHeaders,
		},
		{
			name:       "missing signature returns error",
			signingKey: privateKey,
			modify: func(header http.Header, payload *[]byte) {
				header.Del("webhook-signature")
			},
			expectedErr: standardwebhooks.ErrRequiredHeaders,
		},
		{
			name:        "old timestamp fails",
			signingKey:  privateKey,
			timestamp:   time.Now().Add(tolerance*-1 - time.Second),
			expectedErr: standardwebhooks.ErrMessageTooOld,
		},
		{
			name:        "new timestamp fails",
			signingKey:  privateKey,
			timestamp:   time.Now().Add(tolerance + time.Second),
			expectedErr: standardwebhooks.ErrMessageTooNew,
		},
		{
			name:               "old timestamp passes when ignoring tolerance",
			signingKey:         privateKey,
			timestamp:          time.Now().Add(tolerance*-1 - time.Second),
			noEnforceTimestamp: true,
		},
	}

	for _, tc := range testCases {
		publicKeys := tc.publicKeys
		if publicKeys == nil {
			publicKeys = []string{asymmetricPublicKey}
		}
		endpointID := tc.endpointID
		if endpointID == "" {
			endpointID = asymmetricEndpointID
		}
		timestamp := tc.timestamp
		if timestamp.IsZero() {
			timestamp = time.Now()
		}

		payload := defaultPayload
		header := asymmetricHeaders(defaultMsgID, asymmetricSign(tc.signingKey, asymmetricEndpointID, defaultMsgID, timestamp, payload), timestamp)
		if tc.modify != nil {
			tc.modify(header, &payload)
		}

		wh, err := standardwebhooks.NewWebhookAsymmetric(endpointID, publicKeys)
		if err != nil {
			t.Errorf("%s: %s", tc.name, err)
			continue
		}
		if tc.noEnforceTimestamp {
			err = wh.VerifyIgnoringTimestamp(payload, header)
		} else {
			err = wh.Verify(payload, header)
		}
		if tc.expectedErr == nil && err != nil {
			t.Errorf("%s: failed with err %s but shouldn't have", tc.name, err)
		} else if tc.expectedErr != nil && !errors.Is(err, tc.expectedErr) {
			t.Errorf("%s: expected %s, got %v", tc.name, tc.expectedErr, err)
		}
	}
}

func TestWebhookAsymmetricConstructorErrors(t *testing.T) {
	testCases := []struct {
		name        string
		publicKeys  []string
		endpointID  string
		expectedErr error
	}{
		{"no public keys", []string{}, asymmetricEndpointID, standardwebhooks.ErrNoPublicKeys},
		{"nil public keys", nil, asymmetricEndpointID, standardwebhooks.ErrNoPublicKeys},
		{"missing whpk_ prefix", []string{strings.TrimPrefix(asymmetricPublicKey, "whpk_")}, asymmetricEndpointID, standardwebhooks.ErrInvalidPublicKey},
		{"whsec_ prefix", []string{"whsec_" + strings.TrimPrefix(asymmetricPublicKey, "whpk_")}, asymmetricEndpointID, standardwebhooks.ErrInvalidPublicKey},
		{"invalid base64", []string{"whpk_not base64!"}, asymmetricEndpointID, standardwebhooks.ErrInvalidPublicKey},
		{"key too short", []string{"whpk_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}, asymmetricEndpointID, standardwebhooks.ErrInvalidPublicKey},
		{"empty key", []string{"whpk_"}, asymmetricEndpointID, standardwebhooks.ErrInvalidPublicKey},
		{"one invalid key in the list", []string{asymmetricPublicKey, "whpk_"}, asymmetricEndpointID, standardwebhooks.ErrInvalidPublicKey},
		{"empty endpoint id", []string{asymmetricPublicKey}, "", standardwebhooks.ErrInvalidEndpointID},
		{"endpoint id with a dot", []string{asymmetricPublicKey}, "ep_abc.def", standardwebhooks.ErrInvalidEndpointID},
	}

	for _, tc := range testCases {
		wh, err := standardwebhooks.NewWebhookAsymmetric(tc.endpointID, tc.publicKeys)
		if wh != nil || !errors.Is(err, tc.expectedErr) {
			t.Errorf("%s: expected %s, got %v", tc.name, tc.expectedErr, err)
		}
	}
}

func TestWebhookAsymmetricChallengeResponse(t *testing.T) {
	challenge := "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM="
	expected := "v2a,t0RDFhzk7OtVzgvMsjuXnodSWuby2BVX+zPqw2/ksUk="
	otherPublicKey := asymmetricPublicKeyString(asymmetricPrivateKey(t, asymmetricOtherSecretKey))

	wh, err := standardwebhooks.NewWebhookAsymmetric(asymmetricEndpointID, []string{asymmetricPublicKey, otherPublicKey})
	if err != nil {
		t.Fatal(err)
	}

	response := wh.EndpointVerificationResponse(challenge)
	if response != expected {
		t.Fatalf("challenge response %s != expected challenge response %s", response, expected)
	}
}

func TestWebhookAsymmetricVerifyChallengeResponse(t *testing.T) {
	challenge := "0njH7N3kV5eXPB+/eh+eoA2Ahvz2JgNp0iC/BLOl6yM="
	header := "v2a,t0RDFhzk7OtVzgvMsjuXnodSWuby2BVX+zPqw2/ksUk="
	otherPublicKey := asymmetricPublicKeyString(asymmetricPrivateKey(t, asymmetricOtherSecretKey))

	// The matching key is the second one in the list
	wh, err := standardwebhooks.NewWebhookAsymmetric(asymmetricEndpointID, []string{otherPublicKey, asymmetricPublicKey})
	if err != nil {
		t.Fatal(err)
	}

	if err := wh.VerifyEndpointVerificationResponse(challenge, header); err != nil {
		t.Fatalf("expected challenge response to be valid, got %s", err)
	}

	if err := wh.VerifyEndpointVerificationResponse(challenge, "v2,abc "+header); !errors.Is(err, standardwebhooks.ErrNoMatchingSignature) {
		t.Fatalf("expected %s for a list of signatures, got %v", standardwebhooks.ErrNoMatchingSignature, err)
	}

	if err := wh.VerifyEndpointVerificationResponse("wrong-challenge", header); !errors.Is(err, standardwebhooks.ErrNoMatchingSignature) {
		t.Fatalf("expected %s, got %v", standardwebhooks.ErrNoMatchingSignature, err)
	}

	wh, err = standardwebhooks.NewWebhookAsymmetric("ep_other", []string{asymmetricPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := wh.VerifyEndpointVerificationResponse(challenge, header); !errors.Is(err, standardwebhooks.ErrNoMatchingSignature) {
		t.Fatalf("expected %s for another endpoint id, got %v", standardwebhooks.ErrNoMatchingSignature, err)
	}
}
