package ondccrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestCreateAuthorizationHeader_ExactFormatting(t *testing.T) {
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
