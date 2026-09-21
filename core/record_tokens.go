package core

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/tools/security"
)

// Supported record token types
const (
	TokenTypeAuth          = "auth"
	TokenTypeFile          = "file"
	TokenTypeFileDownload  = "fileDownload"
	TokenTypeVerification  = "verification"
	TokenTypePasswordReset = "passwordReset"
	TokenTypeEmailChange   = "emailChange"
)

// List with commonly used record token claims
const (
	TokenClaimId           = "id"
	TokenClaimType         = "type"
	TokenClaimCollectionId = "collectionId"
	TokenClaimEmail        = "email"
	TokenClaimNewEmail     = "newEmail"
	TokenClaimRefreshable  = "refreshable"
)

// Common token related errors
var (
	ErrNotAuthRecord     = errors.New("not an auth collection record")
	ErrMissingSigningKey = errors.New("missing or invalid signing key")
)

// NewStaticAuthToken generates and returns a new static record authentication token.
//
// Static auth tokens are similar to the regular auth tokens, but are
// non-refreshable and support custom duration.
//
// Zero or negative duration will fallback to the duration from the auth collection settings.
func (m *Record) NewStaticAuthToken(duration time.Duration) (string, error) {
	return m.newAuthToken(duration, false)
}

// NewAuthToken generates and returns a new record authentication token.
func (m *Record) NewAuthToken() (string, error) {
	return m.newAuthToken(0, true)
}

func (m *Record) newAuthToken(duration time.Duration, refreshable bool) (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().AuthToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	claims := jwt.MapClaims{
		TokenClaimType:         TokenTypeAuth,
		TokenClaimId:           m.Id,
		TokenClaimCollectionId: m.Collection().Id,
		TokenClaimRefreshable:  refreshable,
	}

	if duration <= 0 {
		duration = m.Collection().AuthToken.DurationTime()
	}

	return security.NewJWT(claims, key, duration)
}

// NewVerificationToken generates and returns a new record verification token.
func (m *Record) NewVerificationToken() (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().VerificationToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypeVerification,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
			TokenClaimEmail:        m.Email(),
		},
		key,
		m.Collection().VerificationToken.DurationTime(),
	)
}

// NewPasswordResetToken generates and returns a new auth record password reset request token.
func (m *Record) NewPasswordResetToken() (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().PasswordResetToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypePasswordReset,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
			TokenClaimEmail:        m.Email(),
		},
		key,
		m.Collection().PasswordResetToken.DurationTime(),
	)
}

// NewEmailChangeToken generates and returns a new auth record change email request token.
func (m *Record) NewEmailChangeToken(newEmail string) (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().EmailChangeToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypeEmailChange,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
			TokenClaimEmail:        m.Email(),
			TokenClaimNewEmail:     newEmail,
		},
		key,
		m.Collection().EmailChangeToken.DurationTime(),
	)
}

// NewFileToken generates and returns a new record private file access token.
func (m *Record) NewFileToken() (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().FileToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypeFile,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
		},
		key,
		m.Collection().FileToken.DurationTime(),
	)
}

// NewFileDownloadToken generates a new revocable signed file download
// JWT for a single file of the provided target record.
//
// Unlike [Record.NewFileToken], the returned token is bound to exactly
// one collection/record/file/field and doesn't grant access to anything
// else, making it suitable for sharing via email or external processing
// services without browser cookies.
//
// The token is signed with the auth record's token key combined with its
// collection FileToken secret (the same key material as the regular file
// tokens), so rotating the record's tokenKey or changing the collection
// file token secret invalidates all previously issued signed URLs.
//
// The signature binds the target collection, record, file field, filename,
// expiration (exp) and the optional response disposition. The download
// handler cross-checks every claim against the actual request path and
// verifies that the returned jti hasn't been revoked.
//
// The returned id is the token's "jti" claim and is expected to be
// persisted as a [FileToken] revocation row (with the same primary key).
//
// NB! The method doesn't perform access control or file existence checks;
// the caller must verify those before minting and persisting the token.
func (m *Record) NewFileDownloadToken(
	target *Record,
	fileField string,
	filename string,
	disposition string,
	duration time.Duration,
) (token string, id string, err error) {
	if !m.Collection().IsAuth() {
		return "", "", ErrNotAuthRecord
	}

	key := m.TokenKey() + m.Collection().FileToken.Secret
	if key == "" {
		return "", "", ErrMissingSigningKey
	}

	if duration <= 0 {
		duration = m.Collection().FileToken.DurationTime()
	}

	// jti doubles as the revocation row id; keep it within the regular
	// record id alphabet/length so the _fileTokens table can use it as PK.
	id = security.PseudorandomStringWithAlphabet(DefaultIdLength, DefaultIdAlphabet)
	now := time.Now()

	token, err = security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:            TokenTypeFileDownload,
			TokenClaimId:              m.Id,
			TokenClaimCollectionId:    m.Collection().Id,
			TokenClaimFileCollection:  target.Collection().Id,
			TokenClaimFileRecord:      target.Id,
			TokenClaimFileField:       fileField,
			TokenClaimFileFilename:    filename,
			TokenClaimFileDisposition: normalizeFileTokenDisposition(disposition),
			"iat":                     now.Unix(),
			"jti":                     id,
		},
		key,
		duration,
	)

	return token, id, err
}
