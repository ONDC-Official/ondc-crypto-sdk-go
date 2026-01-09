# ondc-crypto-sdk-go

Go implementation of ONDC signing/verification headers with **exact parity** to the Node library `ondc-crypto-sdk-nodejs` in this repo.

## Install

```bash
go get github.com/ONDC-Official/ondc-crypto-sdk-go@v0.2.0
```

## Usage

## Recommended API (with timestamp validation)

These APIs match the required behavior for ONDC authorization header creation and verification:

### Create authorisation header

```go
header, err := ondccrypto.CreateAuthorisationHeader(ondccrypto.CreateAuthorisationHeaderParams{
	Payload:      rawBody,            // exact raw JSON string
	PrivateKey:   privateKeyBase64,   // base64 ed25519 private key: 32-byte seed OR 64-byte private key
	SubscriberID: subscriberID,
	UniqueKeyID:  ukid,
})
```

### Verify authorisation header

```go
ok, err := ondccrypto.VerifyAuthorisationHeader(ondccrypto.VerifyAuthorisationHeaderParams{
	AuthHeader: authHeader,
	Payload:    rawBody,          // must match exactly what was signed
	PublicKey:  publicKeyBase64,  // base64 of 32-byte ed25519 public key
})
```

Behavior:

- Validates timestamps: `created <= now <= expires`
- Returns `(false, error)` on invalid headers/signatures

## Node-parity API (legacy)

These functions mirror the Node SDK behavior exactly, including permissive verification semantics.

### Create Authorization header

```go
header, err := ondccrypto.CreateAuthorizationHeader(ondccrypto.CreateAuthorizationHeaderParams{
	Body:                  rawBody,
	PrivateKey:            privateKeyBase64, // base64 of 64-byte ed25519 private key
	SubscriberID:          subscriberID,
	SubscriberUniqueKeyID: ukid,
	// Created: "1700000000", // optional
	// Expires: "1700003600", // optional
})
```

### Verify Authorization header

```go
ok := ondccrypto.IsHeaderValid(ondccrypto.IsHeaderValidParams{
	Header:    authHeader,
	Body:      rawBody,
	PublicKey: publicKeyBase64, // base64 of 32-byte ed25519 public key
})
```

### VLookup signature

```go
sig, err := ondccrypto.CreateVLookupSignature(ondccrypto.CreateVLookupSignatureParams{
	Country:      "IND",
	Domain:       "ONDC:RET10",
	Type:         "BAP",
	City:         "std:080",
	SubscriberID: "my-subscriber-id",
	PrivateKey:   privateKeyBase64,
})
```

## Notes (parity)

- Digest: BLAKE2b-512 and `digest: BLAKE-512=...` line.
- Signature: Ed25519 detached signature (base64 standard/padded).
- No JSON canonicalization: the exact raw request body string is signed.
- `IsHeaderValid` is permissive like Node: returns `false` on any error and does not enforce expiry.

## Logging

By default the package logs errors via the standard library logger. Disable or replace it:

```go
ondccrypto.SetLogger(nil) // disable
// or
ondccrypto.SetLogger(myLogger)
```
