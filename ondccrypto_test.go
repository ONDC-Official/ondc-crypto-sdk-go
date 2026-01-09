package ondccrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestCreateAuthorizationHeader_ExactFormatting(t *testing.T) {
	origNow := nowUnix
	t.Cleanup(func() { nowUnix = origNow })
	nowUnix = func() int64 { return 1700000000 }

	seed := make([]byte, 32)
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	body := `{"hello":"world"}`
	created := "1700000000"
	expires := "1700003600"

	header, err := CreateAuthorizationHeader(CreateAuthorizationHeaderParams{
		Body:                  body,
		PrivateKey:            privB64,
		SubscriberID:          "sub-id",
		SubscriberUniqueKeyID: "ukid",
		Created:               created,
		Expires:               expires,
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationHeader error: %v", err)
	}

	if gotPrefix := header[:10]; gotPrefix != "Signature " {
		t.Fatalf("expected header prefix 'Signature ', got %q", gotPrefix)
	}

	if !IsHeaderValid(IsHeaderValidParams{Header: header, Body: body, PublicKey: pubB64}) {
		t.Fatalf("expected header to verify")
	}
}

func TestCreateAuthorisationHeaderAndVerifyAuthorisationHeader_SeedPrivateKey(t *testing.T) {
	origNow := nowUnix
	t.Cleanup(func() { nowUnix = origNow })
	nowUnix = func() int64 { return 1700000000 }

	seed := make([]byte, 32)
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(255 - i)
	}
	priv64 := ed25519.NewKeyFromSeed(seed)
	pub := priv64.Public().(ed25519.PublicKey)

	// Requirement: private key may be 32-byte seed.
	privSeedB64 := base64.StdEncoding.EncodeToString(seed)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	payload := `{"x":1,"y":2}`

	header, err := CreateAuthorisationHeader(CreateAuthorisationHeaderParams{
		Payload:      payload,
		PrivateKey:   privSeedB64,
		SubscriberID: "sub",
		UniqueKeyID:  "kid",
	})
	if err != nil {
		t.Fatalf("CreateAuthorisationHeader error: %v", err)
	}

	ok, err := VerifyAuthorisationHeader(VerifyAuthorisationHeaderParams{
		AuthHeader: header,
		Payload:    payload,
		PublicKey:  pubB64,
	})
	if err != nil {
		t.Fatalf("VerifyAuthorisationHeader error: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
}

func TestVerifyAuthorisationHeader_Expired(t *testing.T) {
	origNow := nowUnix
	t.Cleanup(func() { nowUnix = origNow })
	nowUnix = func() int64 { return 1700000000 }

	seed := make([]byte, 32)
	priv64 := ed25519.NewKeyFromSeed(seed)
	pub := priv64.Public().(ed25519.PublicKey)

	privB64 := base64.StdEncoding.EncodeToString(priv64)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	payload := `{"hello":"world"}`

	header, err := CreateAuthorizationHeader(CreateAuthorizationHeaderParams{
		Body:                  payload,
		PrivateKey:            privB64,
		SubscriberID:          "sub-id",
		SubscriberUniqueKeyID: "ukid",
		Created:               "1700000000",
		Expires:               "1700003600",
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationHeader error: %v", err)
	}

	// Move time forward beyond expires.
	nowUnix = func() int64 { return 1700003601 }

	ok, err := VerifyAuthorisationHeader(VerifyAuthorisationHeaderParams{
		AuthHeader: header,
		Payload:    payload,
		PublicKey:  pubB64,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if ok {
		t.Fatalf("expected ok=false")
	}
}

func TestVerifyAuthorisationHeader_PayloadMismatch(t *testing.T) {
	origNow := nowUnix
	t.Cleanup(func() { nowUnix = origNow })
	nowUnix = func() int64 { return 1700000000 }

	seed := make([]byte, 32)
	priv64 := ed25519.NewKeyFromSeed(seed)
	pub := priv64.Public().(ed25519.PublicKey)

	privB64 := base64.StdEncoding.EncodeToString(priv64)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	payload := `{"a":1}`

	header, err := CreateAuthorizationHeader(CreateAuthorizationHeaderParams{
		Body:                  payload,
		PrivateKey:            privB64,
		SubscriberID:          "sub-id",
		SubscriberUniqueKeyID: "ukid",
		Created:               "1700000000",
		Expires:               "1700003600",
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationHeader error: %v", err)
	}

	ok, err := VerifyAuthorisationHeader(VerifyAuthorisationHeaderParams{
		AuthHeader: header,
		Payload:    `{"a":2}`,
		PublicKey:  pubB64,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if ok {
		t.Fatalf("expected ok=false")
	}
}

func TestCreateSigningString_NaNExpiryParity(t *testing.T) {
	signing, createdOut, expiresOut, err := createSigningString("hi", "abc", "")
	if err != nil {
		t.Fatalf("createSigningString error: %v", err)
	}
	if createdOut != "abc" {
		t.Fatalf("expected created 'abc', got %q", createdOut)
	}
	if expiresOut != "NaN" {
		t.Fatalf("expected expires 'NaN', got %q", expiresOut)
	}
	if signing == "" {
		t.Fatalf("expected non-empty signing string")
	}
}
