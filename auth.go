package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	issuer          = "https://auth.example.com" // who created the token
	audience        = "orders-api"               // which API the token is meant for
	accessTokenTTL  = 10 * time.Minute           // short: a stolen token dies fast
	refreshTokenTTL = 30 * 24 * time.Hour
)

// ---------- Passwords ----------

// bcrypt is slow on purpose and adds a random salt, so leaked hashes
// are expensive to crack. Argon2id is the other good choice.
func HashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
}

func CheckPassword(hash []byte, pw string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}

// ---------- Access tokens (JWT) ----------

// The token only says WHO the caller is (sub). It does not carry roles:
// we look those up on every request so changes apply immediately.
type TokenService struct {
	secret []byte
}

func (t *TokenService) IssueAccess(u *User) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{audience},
		Subject:   u.ID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenTTL)),
	}
	// HS256 = one shared secret. With several services, use RS256/EdDSA instead:
	// the auth server signs with a private key, APIs verify with the public key.
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.secret)
}

func (t *TokenService) ParseAccess(raw string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(raw, claims,
		func(*jwt.Token) (any, error) { return t.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), // never trust the token's own "alg" header
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience), // a token made for another API is rejected
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// ---------- Refresh tokens (opaque) ----------

// A refresh token is just 32 random bytes. It means nothing by itself;
// it only works because the server has a record of it.
func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// We store only the hash, so a database leak doesn't hand out live tokens.
func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}
