package ondccrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

type CreateAuthorizationHeaderParams struct {
	Body                  string
	PrivateKey            string
	SubscriberID          string
	SubscriberUniqueKeyID string
	Expires               string
	Created               string
}

type IsHeaderValidParams struct {
	Header    string
	Body      string
	PublicKey string
}

type CreateVLookupSignatureParams struct {
	Country       string
	Domain        string
	Type          string
	City          string
	SubscriberID  string
	PrivateKey    string
}

var authHeaderKVRe = regexp.MustCompile(`\s*([^=]+)=([^,]+)[,]?`)

type Logger interface {
	Printf(format string, v ...any)
}

var logger Logger = log.Default()

// SetLogger allows callers to provide their own logger. Pass nil to disable logging.
func SetLogger(l Logger) {
	logger = l
}

var nowUnix = func() int64 { return time.Now().Unix() }

const defaultTTLSeconds int64 = 60 * 60

type CreateAuthorisationHeaderParams struct {
	Payload     string
	PrivateKey  string
	SubscriberID string
	UniqueKeyID string
}

type VerifyAuthorisationHeaderParams struct {
	AuthHeader string
	Payload    string
	PublicKey  string
}

// CreateAuthorisationHeader creates the ONDC Authorization header.
// This preserves the payload exactly as provided (no JSON parsing/canonicalization).
func CreateAuthorisationHeader(p CreateAuthorisationHeaderParams) (string, error) {
	created := strconv.FormatInt(nowUnix(), 10)
	expires := strconv.FormatInt(nowUnix()+defaultTTLSeconds, 10)

	signingString, _, _, err := createSigningString(p.Payload, created, expires)
	if err != nil {
		logf("CreateAuthorisationHeader: signing string error: %v", err)
		return "", err
	}

	signature, err := signMessage(signingString, p.PrivateKey)
	if err != nil {
		logf("CreateAuthorisationHeader: sign error: %v", err)
		return "", err
	}

	header := fmt.Sprintf(
		`Signature keyId="%s|%s|ed25519",algorithm="ed25519",created="%s",expires="%s",headers="(created) (expires) digest",signature="%s"`,
		p.SubscriberID,
		p.UniqueKeyID,
		created,
		expires,
		signature,
	)
	return header, nil
}

// VerifyAuthorisationHeader verifies the ONDC Authorization header.
// It validates timestamps (created <= now <= expires) and verifies the signature.
// Returns (true, nil) when valid, otherwise (false, error).
func VerifyAuthorisationHeader(p VerifyAuthorisationHeaderParams) (bool, error) {
	parts := splitAuthHeader(p.AuthHeader)
	createdStr, ok := parts["created"]
	if !ok || createdStr == "" {
		return false, errors.New("missing created")
	}
	expiresStr, ok := parts["expires"]
	if !ok || expiresStr == "" {
		return false, errors.New("missing expires")
	}
	signatureB64, ok := parts["signature"]
	if !ok || signatureB64 == "" {
		return false, errors.New("missing signature")
	}

	created, err := strconv.ParseInt(createdStr, 10, 64)
	if err != nil {
		return false, errors.New("invalid created")
	}
	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return false, errors.New("invalid expires")
	}

	now := nowUnix()
	if created > now {
		return false, errors.New("created is in the future")
	}
	if now > expires {
		return false, errors.New("authorization header expired")
	}

	signingString, _, _, err := createSigningString(p.Payload, createdStr, expiresStr)
	if err != nil {
		logf("VerifyAuthorisationHeader: signing string error: %v", err)
		return false, err
	}

	okSig, err := verifyMessage(signatureB64, signingString, p.PublicKey)
	if err != nil {
		logf("VerifyAuthorisationHeader: verify error: %v", err)
		return false, err
	}
	if !okSig {
		return false, errors.New("invalid signature")
	}

	return true, nil
}

func CreateAuthorizationHeader(p CreateAuthorizationHeaderParams) (string, error) {
	signingString, created, expires, err := createSigningString(p.Body, p.Created, p.Expires)
	if err != nil {
		return "", err
	}

	signature, err := signMessage(signingString, p.PrivateKey)
	if err != nil {
		return "", err
	}

	header := fmt.Sprintf(
		`Signature keyId="%s|%s|ed25519",algorithm="ed25519",created="%s",expires="%s",headers="(created) (expires) digest",signature="%s"`,
		p.SubscriberID,
		p.SubscriberUniqueKeyID,
		created,
		expires,
		signature,
	)
	return header, nil
}

func IsHeaderValid(p IsHeaderValidParams) bool {
	defer func() {
		_ = recover()
	}()

	parts := splitAuthHeader(p.Header)
	created, _ := parts["created"]
	expires, _ := parts["expires"]
	signatureB64, _ := parts["signature"]

	signingString, _, _, err := createSigningString(p.Body, created, expires)
	if err != nil {
		return false
	}

	ok, err := verifyMessage(signatureB64, signingString, p.PublicKey)
	if err != nil {
		return false
	}
	return ok
}

func CreateVLookupSignature(p CreateVLookupSignatureParams) (string, error) {
	stringToSign := fmt.Sprintf("%s|%s|%s|%s|%s", p.Country, p.Domain, p.Type, p.City, p.SubscriberID)
	return signMessage(stringToSign, p.PrivateKey)
}

func createSigningString(message, created, expires string) (signingString string, createdOut string, expiresOut string, err error) {
	if created == "" {
		created = strconv.FormatInt(time.Now().Unix(), 10)
	}
	if expires == "" {
		createdInt, parseErr := strconv.ParseInt(created, 10, 64)
		if parseErr != nil {
			expires = "NaN"
		} else {
			expires = strconv.FormatInt(createdInt+1*60*60, 10)
		}
	}

	digestBase64, err := blake512DigestBase64(message)
	if err != nil {
		return "", "", "", err
	}

	signingString = fmt.Sprintf("(created): %s\n(expires): %s\ndigest: BLAKE-512=%s", created, expires, digestBase64)
	return signingString, created, expires, nil
}

func signMessage(signingString, privateKeyB64 string) (string, error) {
	privateKey, err := parseEd25519PrivateKey(privateKeyB64)
	if err != nil {
		return "", err
	}

	sig := ed25519.Sign(privateKey, []byte(signingString))
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verifyMessage(signedStringB64, signingString, publicKeyB64 string) (bool, error) {
	signatureBytes, err := decodeBase64Original(signedStringB64)
	if err != nil {
		return false, err
	}
	publicKeyBytes, err := decodeBase64Original(publicKeyB64)
	if err != nil {
		return false, err
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return false, errors.New("invalid ed25519 signature length")
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return false, errors.New("invalid ed25519 public key length")
	}
	return ed25519.Verify(ed25519.PublicKey(publicKeyBytes), []byte(signingString), signatureBytes), nil
}

func splitAuthHeader(authHeader string) map[string]string {
	header := strings.Replace(authHeader, "Signature ", "", 1)
	parts := map[string]string{}
	matches := authHeaderKVRe.FindAllStringSubmatch(header, -1)
	for _, m := range matches {
		if len(m) >= 3 {
			key := m[1]
			value := removeQuotes(m[2])
			parts[key] = value
		}
	}
	return parts
}

func removeQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first := s[0]
	last := s[len(s)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func blake512DigestBase64(message string) (string, error) {
	h, err := blake2b.New(64, nil)
	if err != nil {
		return "", err
	}
	if _, err := h.Write([]byte(message)); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum), nil
}

func decodeBase64Original(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base64 string")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	// libsodium ORIGINAL accepts standard base64; in practice many callers omit padding.
	b2, err2 := base64.RawStdEncoding.DecodeString(s)
	if err2 == nil {
		return b2, nil
	}
	return nil, err
}

func parseEd25519PrivateKey(privateKeyB64 string) (ed25519.PrivateKey, error) {
	keyBytes, err := decodeBase64Original(privateKeyB64)
	if err != nil {
		return nil, err
	}
	// Requirement: private key may be 32-byte seed or 64-byte expanded private key.
	switch len(keyBytes) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(keyBytes), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(keyBytes), nil
	default:
		return nil, fmt.Errorf("invalid ed25519 private key length: got %d, want %d or %d", len(keyBytes), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func logf(format string, v ...any) {
	if logger == nil {
		return
	}
	logger.Printf(format, v...)
}
