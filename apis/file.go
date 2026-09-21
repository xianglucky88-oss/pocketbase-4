package apis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/filesystem"
	"github.com/pocketbase/pocketbase/tools/list"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/spf13/cast"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
)

var imageContentTypes = []string{"image/png", "image/jpg", "image/jpeg", "image/gif", "image/webp"}
var defaultThumbSizes = []string{"100x100"}

// bindFileApi registers the file api endpoints and the corresponding handlers.
func bindFileApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	maxWorkers := cast.ToInt64(os.Getenv("PB_THUMBS_MAX_WORKERS"))
	if maxWorkers <= 0 {
		maxWorkers = int64(runtime.NumCPU() + 2) // the value is arbitrary chosen and may change in the future
	}

	maxWait := cast.ToInt64(os.Getenv("PB_THUMBS_MAX_WAIT"))
	if maxWait <= 0 {
		maxWait = 60
	}

	api := fileApi{
		thumbGenPending: new(singleflight.Group),
		thumbGenSem:     semaphore.NewWeighted(maxWorkers),
		thumbGenMaxWait: time.Duration(maxWait) * time.Second,
	}

	sub := rg.Group("/files")
	sub.POST("/token", api.fileToken).Bind(RequireAuth())
	sub.POST("/links", api.createFileLink).Bind(RequireAuth())
	sub.GET("/links", api.listFileLinks).Bind(RequireAuth())
	sub.DELETE("/links/{tokenId}", api.revokeFileLink).Bind(RequireAuth())
	sub.GET("/{collection}/{recordId}/{filename}", api.download).Bind(collectionPathRateLimit("", "file"))
}

type fileApi struct {
	// thumbGenSem is a semaphore to prevent too much concurrent
	// requests generating new thumbs at the same time.
	thumbGenSem *semaphore.Weighted

	// thumbGenPending represents a group of currently pending
	// thumb generation processes.
	thumbGenPending *singleflight.Group

	// thumbGenMaxWait is the maximum waiting time for starting a new
	// thumb generation process.
	thumbGenMaxWait time.Duration
}

func (api *fileApi) fileToken(e *core.RequestEvent) error {
	// extra check for just in case the handler is called in a different context
	if e.Auth == nil {
		return e.UnauthorizedError("Missing auth context.", nil)
	}

	token, err := e.Auth.NewFileToken()
	if err != nil {
		return e.InternalServerError("Failed to generate file token", err)
	}

	event := new(core.FileTokenRequestEvent)
	event.RequestEvent = e
	event.Token = token
	event.Record = e.Auth

	return e.App.OnFileTokenRequest().Trigger(event, func(e *core.FileTokenRequestEvent) error {
		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, map[string]string{"token": e.Token})
		})
	})
}

func (api *fileApi) download(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil {
		return e.NotFoundError("", nil)
	}

	recordId := e.Request.PathValue("recordId")
	if recordId == "" {
		return e.NotFoundError("", nil)
	}

	record, err := e.App.FindRecordById(collection, recordId)
	if err != nil {
		return e.NotFoundError("", err)
	}

	filename := e.Request.PathValue("filename")

	fileField := record.FindFileFieldByFile(filename)
	if fileField == nil {
		return e.NotFoundError("", nil)
	}

	queryToken := e.Request.URL.Query().Get("token")

	// revocable signed download URLs are identified by their own token type;
	// the validation logic is shared regardless of the configured storage backend
	// (local filesystem or S3) since both serve through the same handler below.
	var signedClaims *core.FileDownloadTokenClaims
	if isFileDownloadToken(queryToken) {
		signedClaims, err = e.App.VerifyFileDownloadToken(queryToken, collection.Id, record.Id, fileField.Name, filename)
		if err != nil {
			return e.NotFoundError("", err)
		}
	}

	// check whether the request is authorized to view the protected file
	if fileField.Protected {
		originalRequestInfo, err := e.RequestInfo()
		if err != nil {
			return e.InternalServerError("Failed to load request info", err)
		}

		var authRecord *core.Record
		if signedClaims != nil {
			// signed URLs authorize the download on behalf of the auth record
			// that minted them; its current ViewRule is re-evaluated on each
			// request below, so permission changes take effect immediately.
			authRecord = signedClaims.AuthRecord
		} else {
			authRecord, _ = e.App.FindAuthRecordByToken(queryToken, core.TokenTypeFile)
		}

		// reset the auth state if it is superuser and it is not whitelisted
		// (not critical because file tokens are short-lived but checked nonetheless as an extra precaution)
		if authRecord != nil && authRecord.IsSuperuser() {
			allowedIPs := e.App.Settings().SuperuserIPs
			if len(allowedIPs) > 0 && !isIPInList(allowedIPs, e.RealIP()) {
				authRecord = nil
			}
		}

		// create a shallow copy of the cached request data and adjust it to the current auth record (if any)
		requestInfo := *originalRequestInfo
		requestInfo.Context = core.RequestInfoContextProtectedFile
		requestInfo.Auth = authRecord

		if ok, _ := e.App.CanAccessRecord(record, &requestInfo, record.Collection().ViewRule); !ok {
			return e.NotFoundError("", errors.New("insufficient permissions to access the file resource"))
		}
	}

	baseFilesPath := record.BaseFilesPath()

	// fetch the original view file field related record
	if collection.IsView() {
		fileRecord, err := e.App.FindRecordByViewFile(collection.Id, fileField.Name, filename)
		if err != nil {
			return e.NotFoundError("", fmt.Errorf("failed to fetch view file field record: %w", err))
		}
		baseFilesPath = fileRecord.BaseFilesPath()
	}

	fsys, err := e.App.NewFilesystem()
	if err != nil {
		return e.InternalServerError("Filesystem initialization failure.", err)
	}
	defer fsys.Close()

	originalPath := baseFilesPath + "/" + filename

	// signed URLs must not be used to discover/access thumb variants and the
	// file is re-checked to still exist before serving it (covers renames,
	// deletes and external storage changes for both local and S3 backends).
	if signedClaims != nil {
		if exists, _ := fsys.Exists(originalPath); !exists {
			return e.NotFoundError("", errors.New("the signed file no longer exists"))
		}
	}

	event := new(core.FileDownloadRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.Record = record
	event.FileField = fileField
	event.ServedPath = originalPath
	event.ServedName = filename
	event.SignedDownloadClaims = signedClaims

	// check for valid thumb size param
	// (ignored for signed downloads - signed URLs always serve the original file)
	var thumbSize string
	if signedClaims == nil {
		thumbSize = e.Request.URL.Query().Get("thumb")
	}
	if thumbSize != "" && (list.ExistInSlice(thumbSize, defaultThumbSizes) || list.ExistInSlice(thumbSize, fileField.Thumbs)) {
		// extract the original file meta attributes and check it existence
		oAttrs, oAttrsErr := fsys.Attributes(originalPath)
		if oAttrsErr != nil {
			return e.NotFoundError("", err)
		}

		// check if it is an image
		if list.ExistInSlice(oAttrs.ContentType, imageContentTypes) {
			// add thumb size as file suffix
			event.ServedName = thumbSize + "_" + filename
			event.ServedPath = baseFilesPath + "/thumbs_" + filename + "/" + event.ServedName

			// create a new thumb if it doesn't exist
			if exists, _ := fsys.Exists(event.ServedPath); !exists {
				if err := api.createThumb(e, fsys, originalPath, event.ServedPath, thumbSize); err != nil {
					e.App.Logger().Warn(
						"Fallback to original - failed to create thumb "+event.ServedName,
						slog.Any("error", err),
						slog.String("original", originalPath),
						slog.String("thumb", event.ServedPath),
					)

					// fallback to the original
					event.ThumbError = err
					event.ServedName = filename
					event.ServedPath = originalPath
				}
			}
		}
	}

	if thumbSize != "" && event.ThumbError == nil && event.ServedPath == originalPath {
		event.ThumbError = fmt.Errorf("the thumb size %q or the original file format are not supported", thumbSize)
	}

	// clickjacking shouldn't be a concern when serving uploaded files,
	// so it safe to unset the global X-Frame-Options to allow files embedding
	// (note: it is out of the hook to allow users to customize the behavior)
	e.Response.Header().Del("X-Frame-Options")

	// signed responses must not be stored in shared caches because they
	// contain per-URL authorization and can be revoked at any time
	if signedClaims != nil {
		e.Response.Header().Set("Cache-Control", "private, no-store")
	}

	return e.App.OnFileDownloadRequest().Trigger(event, func(e *core.FileDownloadRequestEvent) error {
		if e.SignedDownloadClaims != nil {
			// final revocation re-check as close as possible to reading the file,
			// narrowing the race window with a concurrent revoke/delete
			if _, err := e.App.FindFileTokenById(e.SignedDownloadClaims.JTI); err != nil {
				return e.NotFoundError("", errors.New("the signed download URL has been revoked"))
			}
		}

		err = execAfterSuccessTx(true, e.App, func() error {
			disposition := filesystem.DispositionAuto
			if e.SignedDownloadClaims != nil {
				switch e.SignedDownloadClaims.Disposition {
				case core.FileTokenDispositionInline:
					disposition = filesystem.DispositionInline
				case core.FileTokenDispositionAttachment:
					disposition = filesystem.DispositionAttachment
				}

				return fsys.ServeSigned(e.Response, e.Request, e.ServedPath, e.ServedName, disposition)
			}

			return fsys.ServeWithDisposition(e.Response, e.Request, e.ServedPath, e.ServedName, disposition)
		})
		if err != nil {
			return e.NotFoundError("", err)
		}

		return nil
	})
}

// isFileDownloadToken performs a cheap type sniff of the unverified JWT
// to distinguish revocable signed download tokens from the legacy file tokens.
func isFileDownloadToken(token string) bool {
	if token == "" {
		return false
	}

	claims, err := security.ParseUnverifiedJWTWithLeeway(token, core.DownloadTokenLeeway)
	if err != nil {
		return false
	}

	tokenType, _ := claims[core.TokenClaimType].(string)

	return tokenType == core.TokenTypeFileDownload
}

func (api *fileApi) createThumb(
	e *core.RequestEvent,
	fsys *filesystem.System,
	originalPath string,
	thumbPath string,
	thumbSize string,
) error {
	ch := api.thumbGenPending.DoChan(thumbPath, func() (any, error) {
		ctx, cancel := context.WithTimeout(e.Request.Context(), api.thumbGenMaxWait)
		defer cancel()

		if err := api.thumbGenSem.Acquire(ctx, 1); err != nil {
			return nil, err
		}
		defer api.thumbGenSem.Release(1)

		return nil, fsys.CreateThumb(originalPath, thumbPath, thumbSize)
	})

	res := <-ch

	api.thumbGenPending.Forget(thumbPath)

	return res.Err
}
