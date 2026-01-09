# ondc-crypto-sdk-go

Go implementation of ONDC signing/verification headers with **exact parity** to the Node library `ondc-crypto-sdk-nodejs` in this repo.

## Install

```bash
go get github.com/ONDC-Official/ondc-crypto-sdk-go@v0.1.0
```

## Usage

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
