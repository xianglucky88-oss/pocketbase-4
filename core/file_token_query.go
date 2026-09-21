package core

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/tools/security"
)

// FindFileTokenById returns a single non-expired FileToken by its id
// (the signed URL jti).
//
// Returns sql.ErrNoRows if no matching token row exists or if it is expired
// (expired rows are kept only until the periodic cleanup cron runs).
func (app *BaseApp) FindFileTokenById(id string) (*FileToken, error) {
	result := &FileToken{}

	err := app.RecordQuery(CollectionNameFileTokens).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	if result.HasExpired() {
		return nil, errors.New("the file token is expired")
	}

	return result, nil
}

// FindAllFileTokensByTargetRecord returns all (still valid) FileToken rows
// pointing to the provided target record, ordered by newest first.
func (app *BaseApp) FindAllFileTokensByTargetRecord(target *Record) ([]*FileToken, error) {
	result := []*FileToken{}

	err := app.RecordQuery(CollectionNameFileTokens).
		AndWhere(dbx.HashExp{
			"collectionRef": target.Collection().Id,
			"recordRef":     target.Id,
		}).
		OrderBy("created DESC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteFileToken deletes a single FileToken row, which revokes the
// associated signed URL immediately (the next download re-check fails).
//
// It is safe for concurrent use with in-flight downloads - the download
// handler re-reads the row right before serving the file, so a revocation
// racing with a request either completes before that check (download fails)
// or after it (the single in-flight response is allowed, but every later
// request, including Range/redirect retries, is rejected).
func (app *BaseApp) DeleteFileToken(token *FileToken) error {
	return app.Delete(token)
}

// DeleteAllFileTokensByTargetRecord deletes all FileToken rows associated
// with the provided target record, revoking every signed URL pointing to it
// (regardless of who minted it).
func (app *BaseApp) DeleteAllFileTokensByTargetRecord(target *Record) error {
	models, err := app.FindAllFileTokensByTargetRecord(target)
	if err != nil {
		return err
	}

	var errs []error
	for _, m := range models {
		if err := app.Delete(m); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// DeleteExpiredFileTokens deletes all FileToken rows past their expiration
// (including the [DownloadTokenLeeway] grace period).
func (app *BaseApp) DeleteExpiredFileTokens() error {
	minValidDate := time.Now().Add(-1 * DownloadTokenLeeway)

	items := []*Record{}

	err := app.RecordQuery(CollectionNameFileTokens).
		AndWhere(dbx.NewExp("[[expiresAt]] <= {:date}", dbx.Params{"date": minValidDate.UTC().Format("2006-01-02 15:04:05.000Z")})).
		All(&items)
	if err != nil {
		return err
	}

	for _, item := range items {
		if err := app.Delete(item); err != nil {
			return err
		}
	}

	return nil
}

// FileDownloadTokenClaims holds the verified claims of a signed download URL.
type FileDownloadTokenClaims struct {
	// JTI is the token unique id (also the revocation row PK).
	JTI string

	// AuthRecord is the record on whose behalf the URL was minted
	// and whose ViewRule is re-evaluated on each download.
	AuthRecord *Record

	// CollectionID/RecordID/Field/Filename are the bound target values
	// taken from the signed payload (never from the URL alone).
	CollectionID string
	RecordID     string
	Field        string
	Filename     string
	Disposition  string
}

// VerifyFileDownloadToken verifies a signed file download token for the
// provided request context.
//
// It performs a self-contained, storage-backend agnostic validation
// (the exact same checks run for both local filesystem and S3 storage):
//
//  1. parse the JWT and ensure its type is [TokenTypeFileDownload];
//  2. load the minting auth record and verify the HS256 signature with
//     its tokenKey + collection file token secret, applying
//     [DownloadTokenLeeway] clock skew tolerance to exp/iat;
//  3. ensure the signed collection/record/field/filename claims exactly
//     match the requested ones (a tampered URL pointing to another record
//     or file fails even if the signature itself is otherwise valid);
//  4. ensure the token hasn't been revoked by looking up its jti row and
//     re-checking that the row binding matches the request too;
//  5. ensure the signed expiration hasn't passed.
//
// It does NOT re-evaluate record visibility rules nor check whether the
// file still exists on storage - the download handler does that after
// loading the actual record/filesystem.
func (app *BaseApp) VerifyFileDownloadToken(
	token string,
	collectionID string,
	recordID string,
	field string,
	filename string,
) (*FileDownloadTokenClaims, error) {
	if token == "" {
		return nil, errors.New("missing file download token")
	}

	// steps 1-2: type check + load the minting auth record and verify
	// the HS256 signature (with the DownloadTokenLeeway clock skew tolerance)
	authRecord, err := app.FindAuthRecordByToken(token, TokenTypeFileDownload)
	if err != nil {
		return nil, err
	}

	// the signature was already verified, so the claims can be trusted;
	// ParseUnverifiedJWT is used here only to extract them (the time claims
	// validation is still applied, with the same clock skew leeway).
	claims, err := security.ParseUnverifiedJWTWithLeeway(token, DownloadTokenLeeway)
	if err != nil {
		return nil, err
	}

	data := &FileDownloadTokenClaims{
		AuthRecord:   authRecord,
		CollectionID: tokenStringClaim(claims, TokenClaimFileCollection),
		RecordID:     tokenStringClaim(claims, TokenClaimFileRecord),
		Field:        tokenStringClaim(claims, TokenClaimFileField),
		Filename:     tokenStringClaim(claims, TokenClaimFileFilename),
		Disposition:  normalizeFileTokenDisposition(tokenStringClaim(claims, TokenClaimFileDisposition)),
		JTI:          tokenStringClaim(claims, "jti"),
	}

	// step 3: cross-check every signed binding against the request parameters
	if data.CollectionID == "" || data.RecordID == "" || data.Field == "" || data.Filename == "" {
		return nil, errors.New("the file download token is missing required claims")
	}

	if data.CollectionID != collectionID ||
		data.RecordID != recordID ||
		data.Field != field ||
		data.Filename != filename {
		return nil, errors.New("the file download token doesn't match the requested file")
	}

	if data.JTI == "" {
		return nil, errors.New("missing file download token id")
	}

	// step 4-5: revocation + expiration re-check (fresh DB read, independent
	// of any caches, so concurrent revocations are reflected immediately)
	row, err := app.FindFileTokenById(data.JTI)
	if err != nil {
		return nil, errors.New("the file download token has been revoked or expired")
	}

	// defense in depth: the persisted row must describe the same binding
	if row.CollectionRef() != collectionID ||
		row.RecordRef() != recordID ||
		row.FileField() != field ||
		row.Filename() != filename {
		return nil, errors.New("the file download token revocation record doesn't match the requested file")
	}

	return data, nil
}

// tokenStringClaim extracts a string claim without panicking on missing/wrongly typed values.
func tokenStringClaim(claims jwt.MapClaims, name string) string {
	v, _ := claims[name].(string)
	return v
}
