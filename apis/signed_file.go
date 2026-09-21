package apis

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	validation "github.com/pocketbase/ozzo-validation/v4"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

// looseFilenameRe loosely matches a stored record file name (no path separators).
var looseFilenameRe = regexp.MustCompile(`^[^\./\\][^/\\]+$`)

const (
	// signedFileTokenParam is the query param carrying the signed file token.
	signedFileTokenParam = "signature"

	// defaultSignedFileTokenDurationSeconds is the default token validity returned
	// by the public issue endpoint when no duration is specified.
	defaultSignedFileTokenDurationSeconds = 600 // 10 min

	// maxSignedFileTokenDurationSeconds is the upper bound accepted by the public API.
	maxSignedFileTokenDurationSeconds = core.SignedFileTokenMaxDuration // 24h
)

// signedFileTokenCreateBody is the request body for issuing a signed file URL.
type signedFileTokenCreateBody struct {
	// Collection is the collection name or id that owns the file.
	Collection string `json:"collection" form:"collection"`
	RecordId   string `json:"recordId" form:"recordId"`
	FileField  string `json:"fileField" form:"fileField"`
	Filename   string `json:"filename" form:"filename"`
	// Duration is the token validity in seconds (10..86400, default 600).
	Duration int64 `json:"duration" form:"duration"`
	// Disposition optionally forces the download response type
	// ("", "inline" or "attachment").
	Disposition string `json:"disposition" form:"disposition"`
}

// bindSignedFileApi registers the signed file download token endpoints.
//
// Unlike the regular session-based file token (/api/files/token), these
// endpoints produce standalone, short-lived and revocable URLs that don't
// depend on browser cookies and can be embedded in emails or handed to
// external processing services.
func bindSignedFileApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	api := fileApi{}

	sub := rg.Group("/files")

	// public issue endpoint - any authenticated record that can view the file
	// may mint a signed URL for it (superusers are allowed too).
	//
	// note: no collection-scoped rate limiter is bound because the collection
	// is provided in the request body (the global rate limiter still applies).
	sub.POST("/signed-token", api.signedFileTokenCreate).
		Bind(RequireAuth())

	// superuser-only management endpoints
	sub.GET("/signed-token", api.signedFileTokenList).
		Bind(RequireSuperuserAuth())
	sub.DELETE("/signed-token/{tokenId}", api.signedFileTokenRevoke).
		Bind(RequireSuperuserAuth())
}

// signedFileTokenCreate issues a new signed file download URL.
func (api *fileApi) signedFileTokenCreate(e *core.RequestEvent) error {
	if e.Auth == nil {
		return e.UnauthorizedError("Missing auth context.", nil)
	}

	body := &signedFileTokenCreateBody{}
	if err := e.BindBody(body); err != nil {
		return e.BadRequestError("Failed to read request data.", err)
	}

	if body.Duration == 0 {
		body.Duration = defaultSignedFileTokenDurationSeconds
	}

	if err := validation.ValidateStruct(body,
		validation.Field(&body.Collection, validation.Required),
		validation.Field(&body.RecordId, validation.Required),
		validation.Field(&body.FileField, validation.Required),
		validation.Field(&body.Filename, validation.Required,
			validation.Length(1, 150),
			validation.Match(looseFilenameRe)),
		validation.Field(&body.Duration,
			validation.Min(10),
			validation.Max(maxSignedFileTokenDurationSeconds)),
		validation.Field(&body.Disposition,
			validation.In(
				core.SignedFileDispositionAuto,
				core.SignedFileDispositionInline,
				core.SignedFileDispositionAttachment,
			)),
	); err != nil {
		return e.BadRequestError("An error occurred while validating the submitted data.", err)
	}

	collection, err := e.App.FindCachedCollectionByNameOrId(body.Collection)
	if err != nil {
		return e.NotFoundError("", err)
	}

	record, err := e.App.FindRecordById(collection, body.RecordId)
	if err != nil {
		return e.NotFoundError("", err)
	}

	field := record.Collection().Fields.GetByName(body.FileField)
	fileField, ok := field.(*core.FileField)
	if !ok {
		return e.NotFoundError("", errors.New("the requested field is not a file field"))
	}

	// the requested filename must currently be part of the SPECIFIC field value
	var fileBelongsToField bool
	for _, name := range record.GetStringSlice(fileField.Name) {
		if name == body.Filename {
			fileBelongsToField = true
			break
		}
	}
	if !fileBelongsToField {
		return e.NotFoundError("", errors.New("the requested file doesn't exist in the specified field"))
	}

	// Visibility re-check using the CURRENT auth record (the issuer).
	// This guarantees that a caller can't mint a URL for a record/file it can't view.
	originalRequestInfo, err := e.RequestInfo()
	if err != nil {
		return e.InternalServerError("Failed to load request info", err)
	}

	requestInfo := *originalRequestInfo
	requestInfo.Context = core.RequestInfoContextProtectedFile

	// superuser IP whitelist guard, consistent with the download handler
	if e.Auth.IsSuperuser() {
		allowedIPs := e.App.Settings().SuperuserIPs
		if len(allowedIPs) > 0 && !isIPInList(allowedIPs, e.RealIP()) {
			return e.ForbiddenError("Superuser requests are not allowed from this IP.", nil)
		}
	}

	if ok, _ := e.App.CanAccessRecord(record, &requestInfo, record.Collection().ViewRule); !ok {
		// return 404 (not 403) to avoid leaking the existence of inaccessible records
		return e.NotFoundError("", errors.New("insufficient permissions to access the file resource"))
	}

	result, err := e.App.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:      record,
		FileField:   fileField,
		Filename:    body.Filename,
		Duration:    time.Duration(body.Duration) * time.Second,
		Disposition: body.Disposition,
		Subject:     e.Auth,
	})
	if err != nil {
		return e.BadRequestError("Failed to create signed file token.", err)
	}

	// construct the download URL using the same path shape as /api/files/...
	downloadPath := strings.NewReplacer(
		"{collection}", collection.Name,
		"{recordId}", record.Id,
		"{filename}", body.Filename,
	).Replace("/api/files/{collection}/{recordId}/{filename}")

	signedURL, err := core.BuildSignedFileURL(downloadPath, result.Token)
	if err != nil {
		return e.InternalServerError("Failed to build signed file URL.", err)
	}

	event := new(core.SignedFileTokenRequestEvent)
	event.RequestEvent = e
	event.Record = record
	event.Collection = collection
	event.FileField = fileField
	event.Filename = body.Filename
	event.Token = result.Token
	event.URL = signedURL
	event.ExpiresAt = result.ExpiresAt
	event.Disposition = body.Disposition

	return e.App.OnSignedFileTokenRequest().Trigger(event, func(e *core.SignedFileTokenRequestEvent) error {
		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, map[string]any{
				"url":         e.URL,
				"token":       e.Token,
				"expiresAt":   result.ExpiresAt,
				"disposition": body.Disposition,
				"file": map[string]string{
					"collection": collection.Name,
					"recordId":   record.Id,
					"field":      fileField.Name,
					"filename":   body.Filename,
				},
			})
		})
	})
}

// signedFileTokenList is the superuser-only listing/management endpoint.
//
// It supports filtering by collection (name or id), recordId, fileField,
// filename and/or subjectId.
func (api *fileApi) signedFileTokenList(e *core.RequestEvent) error {
	q := e.Request.URL.Query()

	filter := core.SignedFileTokenListFilter{
		CollectionId: q.Get("collection"),
		RecordId:     q.Get("recordId"),
		FileField:    q.Get("fileField"),
		Filename:     q.Get("filename"),
		SubjectId:    q.Get("subjectId"),
	}

	// allow callers to pass collection name or id
	if cid := filter.CollectionId; cid != "" {
		if c, err := e.App.FindCachedCollectionByNameOrId(cid); err == nil && c != nil {
			filter.CollectionId = c.Id
		}
	}

	items, err := e.App.FindActiveSignedFileTokens(filter)
	if err != nil {
		return e.BadRequestError("Failed to list signed file tokens.", err)
	}

	return e.JSON(http.StatusOK, map[string]any{
		"items": items,
	})
}

// signedFileTokenRevoke revokes a single signed file token by its id/jti.
func (api *fileApi) signedFileTokenRevoke(e *core.RequestEvent) error {
	tokenId := e.Request.PathValue("tokenId")
	if tokenId == "" {
		return e.BadRequestError("Missing token id.", nil)
	}

	event := new(core.SignedFileTokenRevokeEvent)
	event.RequestEvent = e
	event.TokenId = tokenId

	return e.App.OnSignedFileTokenRevokeRequest().Trigger(event, func(e *core.SignedFileTokenRevokeEvent) error {
		if err := e.App.RevokeSignedFileToken(e.TokenId); err != nil {
			if errors.Is(err, core.ErrSignedFileTokenNotFound) {
				return e.NotFoundError("Signed file token not found.", err)
			}
			return e.BadRequestError("Failed to revoke signed file token.", err)
		}

		return e.NoContent(http.StatusNoContent)
	})
}
