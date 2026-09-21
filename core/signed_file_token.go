package core

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/list"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// initSignedFileTokensTable ensures the auxiliary db table that backs the
// revocable signed file tokens exists.
//
// It is safe to call multiple times (IF NOT EXISTS) and is invoked during app
// bootstrap.
func (app *BaseApp) initSignedFileTokensTable() error {
	_, err := app.AuxDB().NewQuery(`
		CREATE TABLE IF NOT EXISTS {{_signedFileTokens}} (
			[[id]]                   TEXT PRIMARY KEY NOT NULL,
			[[collectionId]]         TEXT NOT NULL,
			[[recordId]]             TEXT NOT NULL,
			[[fileField]]            TEXT NOT NULL,
			[[filename]]             TEXT NOT NULL,
			[[disposition]]          TEXT DEFAULT '' NOT NULL,
			[[subjectId]]            TEXT DEFAULT '' NOT NULL,
			[[subjectCollectionId]]  TEXT DEFAULT '' NOT NULL,
			[[created]]              TEXT NOT NULL,
			[[expiresAt]]            TEXT NOT NULL,
			[[revokedAt]]            TEXT DEFAULT '' NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_signedFileTokens_target
			ON {{_signedFileTokens}} ([[collectionId]], [[recordId]], [[fileField]], [[filename]]);

		CREATE INDEX IF NOT EXISTS idx_signedFileTokens_expiresAt
			ON {{_signedFileTokens}} ([[expiresAt]]);
	`).Execute()

	return err
}

// SignedFileTokenOptions defines the options for issuing a new signed file token.
type SignedFileTokenOptions struct {
	// Record is the file owner record (required).
	Record *Record

	// FileField is the file field the token is for (required).
	FileField *FileField

	// Filename is the stored plain filename the token is for (required).
	Filename string

	// Duration is how long the token will be valid.
	//
	// Zero or negative duration falls back to DefaultSignedFileTokenDuration.
	// It is capped to SignedFileTokenMaxDuration.
	Duration time.Duration

	// Disposition optionally forces the download response type
	// (SignedFileDispositionAuto, SignedFileDispositionInline or SignedFileDispositionAttachment).
	Disposition string

	// Subject is the auth record on whose behalf the token is issued (usually e.Auth).
	// It is used when redeeming the token to re-check the record visibility rules.
	Subject *Record
}

// DefaultSignedFileTokenDuration is the default validity duration of an
// issued signed file token when no custom duration is provided.
const DefaultSignedFileTokenDuration = 10 * time.Minute

// signedFileTokenURLParam is the query parameter name carrying the signed token.
const signedFileTokenURLParam = "signature"

// signedFileTokenClaims is the typed claims set of a signed file token JWT.
type signedFileTokenClaims struct {
	jwt.RegisteredClaims

	Type                string `json:"type"`
	CollectionId        string `json:"cid"`
	RecordId            string `json:"rid"`
	FileField           string `json:"field"`
	Filename            string `json:"file"`
	Disposition         string `json:"dsp,omitempty"`
	SubjectId           string `json:"sid,omitempty"`
	SubjectCollectionId string `json:"scid,omitempty"`
}

// SignedFileTokenResult is returned upon successful token issuance.
type SignedFileTokenResult struct {
	Token     string           `json:"token"`
	Model     *SignedFileToken `json:"-"`
	ExpiresAt types.DateTime   `json:"expiresAt"`
}

var signedFileTokenSecretMu sync.Mutex

// signedFileTokensSecret returns the app-level HMAC secret used to sign
// the signed file tokens, generating and persisting a new one on first use.
//
// The secret is stored in the (non-public) _params table and is never
// exposed to API callers.
func (app *BaseApp) signedFileTokensSecret() (string, error) {
	signedFileTokenSecretMu.Lock()
	defer signedFileTokenSecretMu.Unlock()

	param := &Param{}
	err := app.ModelQuery(param).Model(signedFileTokenSecretParamKey, param)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	if param.Id != "" {
		secret := strings.Trim(string(param.Value), `"`)
		if len(secret) >= 30 {
			return secret, nil
		}
	}

	// missing or invalid -> (re)generate
	secret := security.RandomString(signedFileTokenSecretSize)

	// persist as a plain SQL upsert to avoid the model save machinery
	// (the param id is a plain TEXT PRIMARY KEY, so a fixed-key INSERT
	// followed by UPDATE on conflict is deterministic)
	_, insertErr := app.nonconcurrentDB.NewQuery(
		"INSERT OR IGNORE INTO {{_params}} ([[id]], [[value]], [[created]], [[updated]]) " +
			"VALUES ({:id}, {:value}, strftime('%Y-%m-%d %H:%M:%fZ'), strftime('%Y-%m-%d %H:%M:%fZ'))",
	).Bind(dbx.Params{
		"id":    signedFileTokenSecretParamKey,
		"value": `"` + secret + `"`,
	}).Execute()
	if insertErr != nil {
		return "", insertErr
	}

	_, updateErr := app.nonconcurrentDB.NewQuery(
		"UPDATE {{_params}} SET [[value]] = {:value}, [[updated]] = strftime('%Y-%m-%d %H:%M:%fZ') WHERE [[id]] = {:id}",
	).Bind(dbx.Params{
		"id":    signedFileTokenSecretParamKey,
		"value": `"` + secret + `"`,
	}).Execute()
	if updateErr != nil {
		return "", updateErr
	}

	return secret, nil
}

// NewSignedFileToken issues a new stateless JWT for the specified file and
// persists its state in the auxiliary db to allow later revocation.
//
// The returned token is bound to the collection, record, file field, filename,
// expiry and (optionally) the response disposition and the issuer subject.
func (app *BaseApp) NewSignedFileToken(opts SignedFileTokenOptions) (*SignedFileTokenResult, error) {
	if opts.Record == nil {
		return nil, errors.New("missing record")
	}
	if opts.FileField == nil {
		return nil, errors.New("missing file field")
	}
	if opts.Filename == "" {
		return nil, errors.New("missing filename")
	}
	if opts.Record.Collection() == nil {
		return nil, errors.New("the record doesn't have a collection")
	}

	disposition := strings.ToLower(strings.TrimSpace(opts.Disposition))
	switch disposition {
	case SignedFileDispositionAuto, SignedFileDispositionInline, SignedFileDispositionAttachment:
		// valid
	default:
		return nil, fmt.Errorf("invalid disposition %q", opts.Disposition)
	}

	duration := opts.Duration
	if duration <= 0 {
		duration = DefaultSignedFileTokenDuration
	}
	if max := time.Duration(SignedFileTokenMaxDuration) * time.Second; duration > max {
		duration = max
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	jti := security.RandomString(32)

	model := &SignedFileToken{
		CollectionId: opts.Record.Collection().Id,
		RecordId:     opts.Record.Id,
		FileField:    opts.FileField.Name,
		Filename:     opts.Filename,
		Disposition:  disposition,
		Created:      types.NowDateTime(),
		ExpiresAt:    types.NowDateTime().Add(duration),
	}
	model.Id = jti
	model.MarkAsNew()

	if opts.Subject != nil && opts.Subject.Collection() != nil {
		model.SubjectId = opts.Subject.Id
		model.SubjectCollectionId = opts.Subject.Collection().Id
	}

	secret, err := app.signedFileTokensSecret()
	if err != nil {
		return nil, err
	}

	claims := signedFileTokenClaims{
		Type:                SignedFileTokenType,
		CollectionId:        model.CollectionId,
		RecordId:            model.RecordId,
		FileField:           model.FileField,
		Filename:            model.Filename,
		Disposition:         model.Disposition,
		SubjectId:           model.SubjectId,
		SubjectCollectionId: model.SubjectCollectionId,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		return nil, err
	}

	if err := app.AuxSaveNoValidate(model); err != nil {
		return nil, err
	}

	return &SignedFileTokenResult{
		Token:     token,
		Model:     model,
		ExpiresAt: model.ExpiresAt,
	}, nil
}

// SignedFileTokenRedemption holds the resolved state of a successfully
// verified signed file token.
type SignedFileTokenRedemption struct {
	Model      *SignedFileToken
	Collection *Collection
	Record     *Record
	FileField  *FileField
	// Subject is the freshly loaded auth record of the token issuer (if any).
	Subject *Record
	// IssuedBySuperuser is true when the token was issued by a superuser,
	// in which case the valid signature acts as an explicit scoped grant.
	IssuedBySuperuser bool
	// Disposition is the forced response type from the token (or "" for auto).
	Disposition string
}

// RedeemSignedFileToken verifies the provided signed file token against
// the requested file location and returns its resolved state.
//
// It is the single shared verification entry point used by both the
// local and S3 filesystems (the actual backend is selected later via
// app.NewFilesystem(), so this method is backend-agnostic).
//
// It performs (in order):
//  1. JWT signature verification with the app-level secret.
//  2. exp/nbf checks (nbf allows a small clock-skew leeway).
//  3. Persistence lookup (the token must exist).
//  4. Revocation and expiry state check.
//  5. Binding check against the requested collection/record/field/filename.
//  6. Re-fetching the record/field and re-checking the record visibility
//     for the token's original subject (the file must still be accessible).
//  7. Checking that the file still exists on the configured storage backend.
func (app *BaseApp) RedeemSignedFileToken(
	tokenString string,
	requestedCollectionNameOrId string,
	requestedRecordId string,
	requestedFileField string,
	requestedFilename string,
) (*SignedFileTokenRedemption, error) {
	secret, err := app.signedFileTokensSecret()
	if err != nil {
		return nil, err
	}

	claims := &signedFileTokenClaims{}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(time.Duration(signedFileTokenClockSkew)*time.Second),
	)

	parsed, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		// distinguish expired from other signature/parse errors
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrSignedFileTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrSignedFileTokenNotFound, err)
	}
	if parsed == nil || !parsed.Valid {
		return nil, ErrSignedFileTokenNotFound
	}

	if claims.Type != SignedFileTokenType || claims.ID == "" {
		return nil, ErrSignedFileTokenNotFound
	}

	// note: the exp and nbf claims (the latter with the clock-skew leeway)
	// are already validated by the JWT parser above; the checks below against
	// the persisted row are an additional server-side state verification.

	model, err := app.FindSignedFileTokenById(claims.ID)
	if err != nil {
		return nil, ErrSignedFileTokenNotFound
	}

	if model.IsRevoked() {
		return nil, ErrSignedFileTokenRevoked
	}
	if model.HasExpired() {
		return nil, ErrSignedFileTokenExpired
	}

	// (re)load the requested collection/record/field - the URL is never trusted
	collection, err := app.FindCachedCollectionByNameOrId(requestedCollectionNameOrId)
	if err != nil {
		return nil, ErrSignedFileTokenMismatch
	}

	if model.CollectionId != collection.Id {
		return nil, ErrSignedFileTokenMismatch
	}
	if model.RecordId != requestedRecordId ||
		model.FileField != requestedFileField ||
		model.Filename != requestedFilename {
		return nil, ErrSignedFileTokenMismatch
	}

	record, err := app.FindRecordById(collection, requestedRecordId)
	if err != nil {
		return nil, fmt.Errorf("%w: record no longer exists", ErrSignedFileTokenMismatch)
	}

	fileField := record.Collection().Fields.GetByName(requestedFileField)
	if fileField == nil {
		return nil, fmt.Errorf("%w: field no longer exists", ErrSignedFileTokenMismatch)
	}
	typedField, ok := fileField.(*FileField)
	if !ok {
		return nil, fmt.Errorf("%w: field is not a file field", ErrSignedFileTokenMismatch)
	}

	// re-check record visibility based on the token's original subject
	subject, issuedBySuperuser, visibilityErr := app.resolveSignedFileTokenSubject(model)
	if visibilityErr != nil {
		return nil, visibilityErr
	}

	// A superuser-issued signed URL is an explicit, scoped grant: the valid
	// signature authorizes access to this exact file for the token lifetime,
	// so the current (superuser-only) view rule is NOT re-evaluated (doing so
	// would defeat the purpose of sharing a protected file via email/external
	// services). Record existence, field membership, file existence and the
	// revocation/expiry state are still enforced below.
	//
	// For non-superuser subjects the visibility is re-evaluated at redemption
	// time with the freshly loaded subject, so that permission changes take
	// effect immediately even for already-issued URLs.
	if !issuedBySuperuser {
		requestInfo := &RequestInfo{
			Method:  httpMethodGet,
			Context: RequestInfoContextProtectedFile,
			Query:   map[string]string{},
			Headers: map[string]string{},
			Body:    map[string]any{},
			Auth:    subject,
		}
		if ok, _ := app.CanAccessRecord(record, requestInfo, record.Collection().ViewRule); !ok {
			return nil, fmt.Errorf("%w: record is no longer accessible", ErrSignedFileTokenMismatch)
		}
	}

	// check that the file is still part of the SPECIFIC field value
	// (not just any file field, to prevent cross-field filename aliasing)
	if !slices.Contains(record.GetStringSlice(typedField.Name), requestedFilename) {
		return nil, fmt.Errorf("%w: file is no longer attached to the field", ErrSignedFileTokenMismatch)
	}

	// finally check that the physical file still exists on the configured storage backend
	// (works identically for both local and S3 because System wraps both drivers)
	fsys, err := app.NewFilesystem()
	if err != nil {
		return nil, err
	}
	defer fsys.Close()

	baseFilesPath := record.BaseFilesPath()
	if collection.IsView() {
		fileRecord, err := app.FindRecordByViewFile(collection.Id, typedField.Name, requestedFilename)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to resolve view file", ErrSignedFileTokenMismatch)
		}
		baseFilesPath = fileRecord.BaseFilesPath()
	}

	originalPath := baseFilesPath + "/" + requestedFilename
	if exists, _ := fsys.Exists(originalPath); !exists {
		return nil, fmt.Errorf("%w: file no longer exists in storage", ErrSignedFileTokenMismatch)
	}

	return &SignedFileTokenRedemption{
		Model:             model,
		Collection:        collection,
		Record:            record,
		FileField:         typedField,
		Subject:           subject,
		IssuedBySuperuser: issuedBySuperuser,
		Disposition:       model.Disposition,
	}, nil
}

const httpMethodGet = "GET"

// resolveSignedFileTokenSubject loads the auth record that issued the token (if any).
//
// It returns:
//   - subject: the freshly loaded (non-superuser) auth record, or nil.
//   - issuedBySuperuser: true when the token was issued by a superuser; in that
//     case the valid signature is treated as an explicit scoped grant and the
//     view rule is not re-evaluated (no ongoing superuser privileges are
//     inherited either - the subject is still nil).
//
// For regular auth records, the record is reloaded and used to re-evaluate
// the collection view rule at redemption time.
func (app *BaseApp) resolveSignedFileTokenSubject(model *SignedFileToken) (subject *Record, issuedBySuperuser bool, err error) {
	if model.SubjectId == "" || model.SubjectCollectionId == "" {
		return nil, false, nil
	}

	subjectCollection, err := app.FindCachedCollectionByNameOrId(model.SubjectCollectionId)
	if err != nil {
		// subject collection was deleted -> treat as guest (signature is still
		// the authorization proof, and a still-public record will be served)
		return nil, false, nil
	}

	if subjectCollection.Name == CollectionNameSuperusers {
		// superuser explicit grant: skip view-rule re-evaluation but never
		// expose an ongoing superuser auth record to the request context.
		return nil, true, nil
	}

	if !subjectCollection.IsAuth() {
		return nil, false, nil
	}

	subject, err = app.FindRecordById(subjectCollection, model.SubjectId)
	if err != nil {
		// subject no longer exists -> downgrade to guest; access is decided by
		// the (possibly public) view rule, never by privilege inheritance
		return nil, false, nil
	}

	return subject, false, nil
}

// BuildSignedFileURL appends the signed token query parameter to the provided
// (already constructed) file download URL.
func BuildSignedFileURL(baseURL string, token string) (string, error) {
	if token == "" {
		return "", errors.New("missing signed file token")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set(signedFileTokenURLParam, token)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// -------------------------------------------------------------------
// CRUD / revocation helpers
// -------------------------------------------------------------------

// SignedFileTokenQuery returns a new signed file token select query.
func (app *BaseApp) SignedFileTokenQuery() *dbx.SelectQuery {
	return app.AuxModelQuery(&SignedFileToken{})
}

// FindSignedFileTokenById finds a single (active or inactive) signed file token by its jti.
func (app *BaseApp) FindSignedFileTokenById(id string) (*SignedFileToken, error) {
	model := &SignedFileToken{}

	err := app.SignedFileTokenQuery().
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(model)
	if err != nil {
		return nil, err
	}

	return model, nil
}

// SignedFileTokenListFilter allows filtering the active signed file tokens list.
type SignedFileTokenListFilter struct {
	CollectionId string
	RecordId     string
	FileField    string
	Filename     string
	SubjectId    string
}

// FindActiveSignedFileTokens returns the non-revoked, non-expired tokens
// matching the provided filter (all filter fields are optional).
func (app *BaseApp) FindActiveSignedFileTokens(filter SignedFileTokenListFilter) ([]*SignedFileToken, error) {
	result := []*SignedFileToken{}

	nowFormatted := time.Now().UTC().Format(types.DefaultDateLayout)

	query := app.SignedFileTokenQuery().
		AndWhere(dbx.NewExp("[[revokedAt]] = {:empty}", dbx.Params{"empty": ""})).
		AndWhere(dbx.NewExp("[[expiresAt]] >= {:now}", dbx.Params{"now": nowFormatted})).
		OrderBy("created DESC")

	if filter.CollectionId != "" {
		query.AndWhere(dbx.HashExp{"collectionId": filter.CollectionId})
	}
	if filter.RecordId != "" {
		query.AndWhere(dbx.HashExp{"recordId": filter.RecordId})
	}
	if filter.FileField != "" {
		query.AndWhere(dbx.HashExp{"fileField": filter.FileField})
	}
	if filter.Filename != "" {
		query.AndWhere(dbx.HashExp{"filename": filter.Filename})
	}
	if filter.SubjectId != "" {
		query.AndWhere(dbx.HashExp{"subjectId": filter.SubjectId})
	}

	if err := query.All(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// RevokeSignedFileToken marks a single token as revoked.
//
// It is idempotent and concurrency-safe: the revocation is applied as a
// conditional UPDATE (only active rows are affected), so concurrent revoke
// calls can't resurrect or double-revoke a token.
func (app *BaseApp) RevokeSignedFileToken(id string) error {
	nowFormatted := time.Now().UTC().Format(types.DefaultDateLayout)

	res, err := app.auxNonconcurrentDB.
		Update((&SignedFileToken{}).TableName(), dbx.Params{
			"revokedAt": nowFormatted,
		}, dbx.NewExp("[[id]] = {:id} AND [[revokedAt]] = {:empty}", dbx.Params{
			"id":    id,
			"empty": "",
		})).
		Execute()
	if err != nil {
		return err
	}

	if n, _ := res.RowsAffected(); n == 0 {
		// either doesn't exist, already revoked or was revoked concurrently;
		// verify existence to return a meaningful error
		if _, findErr := app.FindSignedFileTokenById(id); findErr != nil {
			return ErrSignedFileTokenNotFound
		}
	}

	return nil
}

// RevokeSignedFileTokens marks all matching active tokens as revoked in bulk.
//
// All filter fields are optional; an empty filter revokes nothing to prevent
// accidental mass revocation.
func (app *BaseApp) RevokeSignedFileTokens(filter SignedFileTokenListFilter) (int64, error) {
	if filter.CollectionId == "" && filter.RecordId == "" &&
		filter.FileField == "" && filter.Filename == "" && filter.SubjectId == "" {
		return 0, errors.New("at least one filter must be provided when bulk revoking signed file tokens")
	}

	nowFormatted := time.Now().UTC().Format(types.DefaultDateLayout)

	expr := dbx.NewExp("[[revokedAt]] = {:empty}", dbx.Params{"empty": ""})
	if filter.CollectionId != "" {
		expr = dbx.And(expr, dbx.HashExp{"collectionId": filter.CollectionId})
	}
	if filter.RecordId != "" {
		expr = dbx.And(expr, dbx.HashExp{"recordId": filter.RecordId})
	}
	if filter.FileField != "" {
		expr = dbx.And(expr, dbx.HashExp{"fileField": filter.FileField})
	}
	if filter.Filename != "" {
		expr = dbx.And(expr, dbx.HashExp{"filename": filter.Filename})
	}
	if filter.SubjectId != "" {
		expr = dbx.And(expr, dbx.HashExp{"subjectId": filter.SubjectId})
	}

	res, err := app.auxNonconcurrentDB.
		Update((&SignedFileToken{}).TableName(), dbx.Params{"revokedAt": nowFormatted}, expr).
		Execute()
	if err != nil {
		return 0, err
	}

	n, _ := res.RowsAffected()
	return n, nil
}

// RevokeAllSignedFileTokensForFile revokes every active token bound to the
// provided collection/record/field/filename tuple.
func (app *BaseApp) RevokeAllSignedFileTokensForFile(collectionId, recordId, fileField, filename string) (int64, error) {
	return app.RevokeSignedFileTokens(SignedFileTokenListFilter{
		CollectionId: collectionId,
		RecordId:     recordId,
		FileField:    fileField,
		Filename:     filename,
	})
}

// DeleteExpiredSignedFileTokens permanently deletes expired (and already
// revoked) token rows that are past their expiry.
//
// For performance the delete is executed as plain SQL (no model events fire).
func (app *BaseApp) DeleteExpiredSignedFileTokens() error {
	nowFormatted := time.Now().UTC().Format(types.DefaultDateLayout)

	_, err := app.auxNonconcurrentDB.
		Delete((&SignedFileToken{}).TableName(), dbx.NewExp("[[expiresAt]] < {:now}", dbx.Params{
			"now": nowFormatted,
		})).
		Execute()

	return err
}

// registerSignedFileTokenHooks wires up:
//   - hourly cleanup of expired signed file token rows.
//   - automatic bulk revocation of the signed file tokens bound to a record
//     when the record is deleted.
//   - automatic revocation of tokens for files that were removed/renamed
//     when a record is updated (so that a renamed file invalidates old URLs).
func (app *BaseApp) registerSignedFileTokenHooks() {
	// run hourly to cleanup expired token rows
	app.Cron().Add("__pbSignedFileTokensCleanup__", "10 * * * *", func() {
		if err := app.DeleteExpiredSignedFileTokens(); err != nil {
			app.Logger().Warn("Failed to delete expired signed file tokens", "error", err)
		}
	})

	// revoke all tokens of a deleted record (runs after a successful delete commit)
	app.OnRecordAfterDeleteSuccess().Bind(&hook.Handler[*RecordEvent]{
		Id:       "__pbSignedFileTokensRecordDelete__",
		Priority: 99,
		Func: func(e *RecordEvent) error {
			collection := e.Record.Collection()
			if collection == nil || collection.IsView() {
				return e.Next()
			}

			revoked, err := e.App.RevokeSignedFileTokens(SignedFileTokenListFilter{
				CollectionId: collection.Id,
				RecordId:     e.Record.Id,
			})
			if err != nil {
				e.App.Logger().Warn(
					"Failed to revoke signed file tokens after record delete",
					"error", err,
					"collectionId", collection.Id,
					"recordId", e.Record.Id,
				)
			} else if revoked > 0 {
				e.App.Logger().Debug(
					"Revoked signed file tokens due to record deletion",
					"count", revoked,
					"recordId", e.Record.Id,
				)
			}

			return e.Next()
		},
	})

	// revoke tokens for files that disappeared from a file field
	// (renamed/replaced/removed) after a successful record update
	app.OnRecordAfterUpdateSuccess().Bind(&hook.Handler[*RecordEvent]{
		Id:       "__pbSignedFileTokensRecordUpdate__",
		Priority: 99,
		Func: func(e *RecordEvent) error {
			collection := e.Record.Collection()
			if collection == nil || collection.IsView() {
				return e.Next()
			}

			original := e.Record.Original()
			if original.IsNew() {
				return e.Next()
			}

			for _, field := range collection.Fields {
				fileField, ok := field.(*FileField)
				if !ok {
					continue
				}

				oldFiles := toStringSlice(original.GetRaw(fileField.Name))
				newFiles := toStringSlice(e.Record.GetRaw(fileField.Name))
				if len(oldFiles) == 0 {
					continue
				}

				newSet := make(map[string]struct{}, len(newFiles))
				for _, f := range newFiles {
					newSet[f] = struct{}{}
				}

				for _, oldFile := range oldFiles {
					if oldFile == "" {
						continue
					}
					if _, exists := newSet[oldFile]; exists {
						continue // file unchanged
					}

					// the file was renamed/replaced/removed -> revoke its tokens
					if _, err := e.App.RevokeAllSignedFileTokensForFile(
						collection.Id, e.Record.Id, fileField.Name, oldFile,
					); err != nil {
						e.App.Logger().Warn(
							"Failed to revoke signed file tokens after file change",
							"error", err,
							"collectionId", collection.Id,
							"recordId", e.Record.Id,
							"field", fileField.Name,
							"filename", oldFile,
						)
					}
				}
			}

			return e.Next()
		},
	})
}

// toStringSlice normalizes a single/multi file field raw value into []string.
func toStringSlice(raw any) []string {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	default:
		return list.ToUniqueStringSlice(v)
	}
}
