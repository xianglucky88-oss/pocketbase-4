package core

import (
	"errors"
	"time"

	"github.com/pocketbase/pocketbase/tools/types"
)

const SignedFileTokensTableName = "_signedFileTokens"

const (
	// SignedFileTokenType is the JWT "type" claim value used for
	// the revocable short-lived signed file download URLs.
	SignedFileTokenType = "fileDownload"

	// signedFileTokenSecretParamKey is the _params id under which the
	// app-level HMAC signing secret of the signed file tokens is stored.
	signedFileTokenSecretParamKey = "@signedFileTokensSecret"

	// signedFileTokenSecretSize is the length in characters of the
	// auto-generated signed file tokens HMAC signing secret.
	signedFileTokenSecretSize = 64

	// SignedFileTokenMaxDuration is the maximum allowed validity duration
	// of a single signed file token.
	SignedFileTokenMaxDuration = 24 * 60 * 60 // 24h in seconds

	// signedFileTokenClockSkew is the JWT validation leeway (in seconds) used
	// to explicitly accommodate minor clock differences between the signer and
	// the verifier for the "nbf" (and, at the JWT layer, "exp") claims.
	//
	// The persisted token row is additionally checked with a strict expiry,
	// so the effective end-of-life remains exact even within the JWT leeway.
	signedFileTokenClockSkew = 60 // seconds
)

// Signed file token JWT claim keys.
const (
	SignedFileTokenClaimType                = "type"
	SignedFileTokenClaimId                  = "jti"
	SignedFileTokenClaimCollectionId        = "cid"
	SignedFileTokenClaimRecordId            = "rid"
	SignedFileTokenClaimFileField           = "field"
	SignedFileTokenClaimFilename            = "file"
	SignedFileTokenClaimDisposition         = "dsp"
	SignedFileTokenClaimSubjectId           = "sid"
	SignedFileTokenClaimSubjectCollectionId = "scid"
)

// Download response disposition values that can be embedded in a signed token.
const (
	// SignedFileDispositionAuto preserves the default content-type driven
	// behavior (inline for images/pdf/video, attachment otherwise).
	SignedFileDispositionAuto = ""

	// SignedFileDispositionInline forces inline serving.
	SignedFileDispositionInline = "inline"

	// SignedFileDispositionAttachment forces "Content-Disposition: attachment".
	SignedFileDispositionAttachment = "attachment"
)

var (
	_ Model = (*SignedFileToken)(nil)
)

// SignedFileToken is an aux db model representing a single issued
// (and potentially revoked) signed file download token.
//
// The actual token is a stateless HS256 JWT whose "jti" claim matches
// SignedFileToken.Id, but its state (revocation, expiry) is tracked in
// the auxiliary database to allow server-side revocation.
type SignedFileToken struct {
	BaseModel

	// CollectionId is the id of the collection that owns the file (at issuing time).
	CollectionId string `db:"collectionId" json:"collectionId"`

	// RecordId is the id of the record that owns the file (at issuing time).
	RecordId string `db:"recordId" json:"recordId"`

	// FileField is the name of the file field.
	FileField string `db:"fileField" json:"fileField"`

	// Filename is the plain (stored) filename.
	Filename string `db:"filename" json:"filename"`

	// Disposition is the optional forced download response type ("", "inline" or "attachment").
	Disposition string `db:"disposition" json:"disposition"`

	// SubjectId is the id of the auth record on whose behalf the token was issued.
	// Empty for guests (guests can't issue, but kept for future-proofing).
	SubjectId string `db:"subjectId" json:"subjectId"`

	// SubjectCollectionId is the collection id of the issuer auth record.
	SubjectCollectionId string `db:"subjectCollectionId" json:"subjectCollectionId"`

	Created   types.DateTime `db:"created" json:"created"`
	ExpiresAt types.DateTime `db:"expiresAt" json:"expiresAt"`

	// RevokedAt is zero if the token is still active; otherwise it holds
	// the time the token was revoked.
	RevokedAt types.DateTime `db:"revokedAt" json:"revokedAt"`
}

// TableName implements [Model.TableName].
func (m *SignedFileToken) TableName() string {
	return SignedFileTokensTableName
}

// IsRevoked reports whether the token was explicitly revoked.
func (m *SignedFileToken) IsRevoked() bool {
	return !m.RevokedAt.IsZero()
}

// HasExpired reports whether the token is past its expiry time.
//
// An optional "now" time can be passed for testing; time.Now() is used otherwise.
func (m *SignedFileToken) HasExpired(optNow ...time.Time) bool {
	now := time.Now()
	if len(optNow) > 0 && !optNow[0].IsZero() {
		now = optNow[0]
	}
	return !m.ExpiresAt.IsZero() && now.After(m.ExpiresAt.Time())
}

// IsActive reports whether the token is neither revoked nor expired.
//
// An optional "now" time can be passed for testing; time.Now() is used otherwise.
func (m *SignedFileToken) IsActive(optNow ...time.Time) bool {
	return !m.IsRevoked() && !m.HasExpired(optNow...)
}

// TargetKey returns an opaque identifier for the (collection, record, field, file)
// tuple the token is bound to.
//
// It is mainly used for logging and bulk operations.
func (m *SignedFileToken) TargetKey() string {
	return m.CollectionId + "/" + m.RecordId + "/" + m.FileField + "/" + m.Filename
}

var (
	// ErrSignedFileTokenNotFound is returned when no persisted token matches the provided jti.
	ErrSignedFileTokenNotFound = errors.New("signed file token not found or is no longer valid")

	// ErrSignedFileTokenRevoked is returned when a token was explicitly revoked.
	ErrSignedFileTokenRevoked = errors.New("signed file token has been revoked")

	// ErrSignedFileTokenExpired is returned when a token is past its expiry time.
	ErrSignedFileTokenExpired = errors.New("signed file token has expired")

	// ErrSignedFileTokenNotYetValid is returned when a token is presented before its "nbf" time.
	ErrSignedFileTokenNotYetValid = errors.New("signed file token is not valid yet")

	// ErrSignedFileTokenMismatch is returned when a token claim doesn't match
	// the requested collection/record/field/file.
	ErrSignedFileTokenMismatch = errors.New("signed file token doesn't match the requested file")
)
