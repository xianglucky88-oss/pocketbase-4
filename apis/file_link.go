package apis

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

// signed file download URL constraints
const (
	fileLinkMinDuration = 1 * time.Minute
	fileLinkMaxDuration = 7 * 24 * time.Hour
)

type fileLinkCreateRequest struct {
	Collection  string `json:"collection" form:"collection"`
	Record      string `json:"record" form:"record"`
	FileField   string `json:"fileField" form:"fileField"`
	File        string `json:"file" form:"file"`
	Duration    int64  `json:"duration" form:"duration"`       // seconds; 0 falls back to 10 minutes
	Disposition string `json:"disposition" form:"disposition"` // auto (default), inline or attachment
}

// fileLinkResponse is returned when a new signed URL is minted.
//
// Only the short-lived token and the derived URL are exposed - the response
// never contains the raw storage key, the minting record's long-lived tokens
// or any superuser credentials.
type fileLinkResponse struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Token       string `json:"token"`
	Collection  string `json:"collection"`
	Record      string `json:"record"`
	FileField   string `json:"fileField"`
	File        string `json:"file"`
	Disposition string `json:"disposition"`
	ExpiresAt   string `json:"expiresAt"`
}

// createFileLink mints a new revocable signed download URL for a single
// record file.
//
// Requires an authenticated request:
//   - superusers can mint links for any record/file;
//   - any other auth record can mint a link only if it currently satisfies
//     the target collection's ViewRule (the same rule is re-checked on
//     every download, so the URL stops working if access is later revoked).
func (api *fileApi) createFileLink(e *core.RequestEvent) error {
	if e.Auth == nil {
		return e.UnauthorizedError("Missing auth context.", nil)
	}

	form := &fileLinkCreateRequest{
		Duration:    int64((10 * time.Minute).Seconds()),
		Disposition: core.FileTokenDispositionAuto,
	}
	if err := e.BindBody(form); err != nil {
		return firstApiError(err, e.BadRequestError("Failed to read request data.", err))
	}
	if form.Collection == "" {
		form.Collection = e.Request.PathValue("collection")
	}
	if form.Record == "" {
		form.Record = e.Request.PathValue("recordId")
	}

	collection, err := e.App.FindCachedCollectionByNameOrId(form.Collection)
	if err != nil {
		return e.NotFoundError("", err)
	}

	record, err := e.App.FindRecordById(collection, form.Record)
	if err != nil {
		return e.NotFoundError("", err)
	}

	fileField := record.FindFileFieldByFile(form.File)
	if fileField == nil {
		// fall back to an explicit field name when the filename couldn't be matched
		if form.FileField != "" {
			if f := collection.Fields.GetByName(form.FileField); f != nil {
				if ff, ok := f.(*core.FileField); ok {
					fileField = ff
				}
			}
		}
	}
	if fileField == nil {
		return e.BadRequestError("The requested file doesn't exist or is not part of a file field.", nil)
	}

	form.FileField = fileField.Name

	// ensure the file still exists on the configured storage backend
	// (local filesystem or S3 share the same System abstraction)
	fsys, err := e.App.NewFilesystem()
	if err != nil {
		return e.InternalServerError("Filesystem initialization failure.", err)
	}
	storagePath := record.BaseFilesPath()
	if collection.IsView() {
		fileRecord, err := e.App.FindRecordByViewFile(collection.Id, fileField.Name, form.File)
		if err != nil {
			return e.BadRequestError("The requested file doesn't exist.", nil)
		}
		storagePath = fileRecord.BaseFilesPath()
	}
	exists, err := fsys.Exists(storagePath + "/" + form.File)
	fsys.Close()
	if err != nil {
		return e.InternalServerError("Failed to verify that the file exists.", err)
	}
	if !exists {
		return e.BadRequestError("The requested file doesn't exist.", nil)
	}

	disposition, err := normalizeLinkDisposition(form.Disposition)
	if err != nil {
		return e.BadRequestError(err.Error(), nil)
	}

	duration := time.Duration(form.Duration) * time.Second
	if duration < fileLinkMinDuration || duration > fileLinkMaxDuration {
		return e.BadRequestError("The duration must be between 1 minute and 7 days.", nil)
	}

	// access control: superusers bypass rules; everyone else must satisfy
	// the current ViewRule at minting time (and again on each download)
	if !e.HasSuperuserAuth() {
		requestInfo, err := e.RequestInfo()
		if err != nil {
			return e.InternalServerError("Failed to load request info", err)
		}
		requestInfo.Context = core.RequestInfoContextProtectedFile

		if ok, _ := e.App.CanAccessRecord(record, requestInfo, record.Collection().ViewRule); !ok {
			return e.NotFoundError("", errors.New("insufficient permissions to create a download link for the file"))
		}
	}

	var (
		token    string
		tokenID  string
		expireAt types.DateTime
	)

	// persist the revocation row and sign the JWT atomically so that no URL
	// can exist without a backing revocable row
	txErr := e.App.RunInTransaction(func(txApp core.App) error {
		expireAt = types.NowDateTime().Add(duration)

		model := core.NewFileToken(txApp)
		model.MarkAsNew()
		model.SetCollectionRef(collection.Id)
		model.SetRecordRef(record.Id)
		model.SetFileField(fileField.Name)
		model.SetFilename(form.File)
		model.SetDisposition(disposition)
		model.SetCreatedByCollection(e.Auth.Collection().Id)
		model.SetCreatedBy(e.Auth.Id)
		model.SetExpiresAt(expireAt)

		var signErr error
		token, tokenID, signErr = e.Auth.NewFileDownloadToken(record, fileField.Name, form.File, disposition, duration)
		if signErr != nil {
			return signErr
		}

		model.Id = tokenID

		return txApp.Save(model)
	})
	if txErr != nil {
		return e.InternalServerError("Failed to create signed download URL.", txErr)
	}

	u := buildSignedFileURL(e, collection, record, form.File, token)

	return e.JSON(http.StatusOK, &fileLinkResponse{
		ID:          tokenID,
		URL:         u,
		Token:       token,
		Collection:  collection.Name,
		Record:      record.Id,
		FileField:   fileField.Name,
		File:        form.File,
		Disposition: disposition,
		ExpiresAt:   expireAt.String(),
	})
}

// fileLinkItem is a single entry returned by the list endpoint.
//
// Note that the signed URL (and its secret token) is intentionally NOT
// included here - it is returned only once at generation time. Existing
// links are listed just so they can be identified and revoked.
type fileLinkItem struct {
	ID          string `json:"id"`
	Collection  string `json:"collection"`
	Record      string `json:"record"`
	FileField   string `json:"fileField"`
	File        string `json:"file"`
	Disposition string `json:"disposition"`
	Created     string `json:"created"`
	ExpiresAt   string `json:"expiresAt"`
}

// listFileLinks lists the still-valid signed URLs minted for a record file.
//
// Superusers see all links for the target record; other auth records see
// only the links they minted. Access to the target record itself is still
// required.
func (api *fileApi) listFileLinks(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.URL.Query().Get("collection"))
	if err != nil {
		return e.NotFoundError("", err)
	}

	record, err := e.App.FindRecordById(collection, e.Request.URL.Query().Get("record"))
	if err != nil {
		return e.NotFoundError("", err)
	}

	if !e.HasSuperuserAuth() {
		requestInfo, err := e.RequestInfo()
		if err != nil {
			return e.InternalServerError("Failed to load request info", err)
		}
		requestInfo.Context = core.RequestInfoContextProtectedFile

		if ok, _ := e.App.CanAccessRecord(record, requestInfo, record.Collection().ViewRule); !ok {
			return e.NotFoundError("", errors.New("insufficient permissions to list the download links"))
		}
	}

	rows, err := e.App.FindAllFileTokensByTargetRecord(record)
	if err != nil {
		return e.InternalServerError("Failed to fetch the signed download URLs.", err)
	}

	filenameFilter := e.Request.URL.Query().Get("file")

	result := make([]fileLinkItem, 0, len(rows))
	for _, row := range rows {
		if row.HasExpired() {
			continue
		}
		if !e.HasSuperuserAuth() &&
			(row.CreatedBy() != e.Auth.Id || row.CreatedByCollection() != e.Auth.Collection().Id) {
			continue
		}
		if filenameFilter != "" && row.Filename() != filenameFilter {
			continue
		}

		result = append(result, fileLinkItem{
			ID:          row.Id,
			Collection:  collection.Name,
			Record:      record.Id,
			FileField:   row.FileField(),
			File:        row.Filename(),
			Disposition: row.Disposition(),
			Created:     row.GetDateTime("created").String(),
			ExpiresAt:   row.ExpiresAt().String(),
		})
	}

	return e.JSON(http.StatusOK, map[string]any{"items": result})
}

// revokeFileLink revokes a single signed download URL.
//
// Superusers can revoke any URL; other auth records can revoke only URLs
// they minted. Revoking an already revoked/expired URL is a no-op (204).
func (api *fileApi) revokeFileLink(e *core.RequestEvent) error {
	tokenId := e.Request.PathValue("tokenId")
	if tokenId == "" {
		return e.BadRequestError("Missing signed URL id.", nil)
	}

	row, err := e.App.FindFileTokenById(tokenId)
	if err != nil {
		// already expired/revoked
		return e.NoContent(http.StatusNoContent)
	}

	if !e.HasSuperuserAuth() &&
		(row.CreatedBy() != e.Auth.Id || row.CreatedByCollection() != e.Auth.Collection().Id) {
		return e.NotFoundError("", nil)
	}

	if err := e.App.DeleteFileToken(row); err != nil {
		return e.InternalServerError("Failed to revoke the signed download URL.", err)
	}

	return e.NoContent(http.StatusNoContent)
}

// -------------------------------------------------------------------

func normalizeLinkDisposition(disposition string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(disposition)) {
	case "", core.FileTokenDispositionAuto:
		return core.FileTokenDispositionAuto, nil
	case core.FileTokenDispositionInline:
		return core.FileTokenDispositionInline, nil
	case core.FileTokenDispositionAttachment:
		return core.FileTokenDispositionAttachment, nil
	default:
		return "", errors.New(`disposition must be one of "auto", "inline" or "attachment"`)
	}
}

// buildSignedFileURL constructs the absolute signed download URL.
//
// When token is empty it returns just the unsigned base URL (eg. for list
// responses where the token itself is not exposed).
func buildSignedFileURL(e *core.RequestEvent, collection *core.Collection, record *core.Record, filename string, token string) string {
	path := "/api/files/" +
		url.PathEscape(collection.Name) + "/" +
		url.PathEscape(record.Id) + "/" +
		url.PathEscape(filename)

	q := url.Values{}
	if token != "" {
		q.Set("token", token)
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	scheme := "http"
	if e.Request.TLS != nil {
		scheme = "https"
	}
	if forwarded := e.Request.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.Split(forwarded, ",")[0]
	}

	return scheme + "://" + e.Request.Host + path
}
