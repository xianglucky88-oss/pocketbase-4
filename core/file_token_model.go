package core

import (
	"context"
	"errors"
	"time"

	"github.com/pocketbase/pocketbase/tools/types"
)

const CollectionNameFileTokens = "_fileTokens"

// Supported download response dispositions embedded in the signed URL.
const (
	// FileTokenDispositionAuto keeps the default Serve behavior
	// (inline for images/video/audio/pdf, attachment for everything else).
	FileTokenDispositionAuto = "auto"

	// FileTokenDispositionInline forces the file to be served inline.
	FileTokenDispositionInline = "inline"

	// FileTokenDispositionAttachment forces "Content-Disposition: attachment".
	FileTokenDispositionAttachment = "attachment"
)

// File download token related JWT claim names.
const (
	TokenClaimFileCollection  = "fileCollectionId"
	TokenClaimFileRecord      = "fileRecordId"
	TokenClaimFileField       = "fileField"
	TokenClaimFileFilename    = "filename"
	TokenClaimFileDisposition = "disposition"
)

// DownloadTokenLeeway is the clock skew tolerance applied when
// verifying a signed download URL (used for the exp/iat claims).
//
// It exists to handle minor clock differences between the server that
// mints a URL and the one that verifies it; expired tokens remain
// rejected once the leeway period has elapsed.
const DownloadTokenLeeway = 60 * time.Second

var (
	_ Model        = (*FileToken)(nil)
	_ PreValidator = (*FileToken)(nil)
	_ RecordProxy  = (*FileToken)(nil)
)

// FileToken defines a Record proxy for working with the _fileTokens collection.
//
// Each row represents a single non-expired signed download URL that can
// still be revoked. Revoking a URL is done by deleting its row; the download
// handler re-checks the row existence right before serving the file.
//
// Expired rows are periodically cleaned up by a cron job.
type FileToken struct {
	*Record
}

// NewFileToken instantiates and returns a new blank *FileToken model.
func NewFileToken(app App) *FileToken {
	m := &FileToken{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameFileTokens)
	if err != nil {
		// this is just to make tests easier since the collection is a system one
		// (note: the loaded record is further checked on FileToken.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *FileToken) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameFileTokens {
		return errors.New("missing or invalid file token ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *FileToken) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *FileToken) SetProxyRecord(record *Record) {
	m.Record = record
}

// CollectionRef returns the target record collection id.
func (m *FileToken) CollectionRef() string {
	return m.GetString("collectionRef")
}

// SetCollectionRef updates the target record collection id.
func (m *FileToken) SetCollectionRef(collectionId string) {
	m.Set("collectionRef", collectionId)
}

// RecordRef returns the target record id.
func (m *FileToken) RecordRef() string {
	return m.GetString("recordRef")
}

// SetRecordRef updates the target record id.
func (m *FileToken) SetRecordRef(recordId string) {
	m.Set("recordRef", recordId)
}

// FileField returns the bound file field name.
func (m *FileToken) FileField() string {
	return m.GetString("fileField")
}

// SetFileField updates the bound file field name.
func (m *FileToken) SetFileField(field string) {
	m.Set("fileField", field)
}

// Filename returns the bound file name.
func (m *FileToken) Filename() string {
	return m.GetString("filename")
}

// SetFilename updates the bound file name.
func (m *FileToken) SetFilename(filename string) {
	m.Set("filename", filename)
}

// Disposition returns the signed response disposition.
func (m *FileToken) Disposition() string {
	return m.GetString("disposition")
}

// SetDisposition updates the signed response disposition.
func (m *FileToken) SetDisposition(disposition string) {
	m.Set("disposition", normalizeFileTokenDisposition(disposition))
}

// CreatedByCollection returns the collection id of the auth record
// on whose behalf the URL was minted.
func (m *FileToken) CreatedByCollection() string {
	return m.GetString("createdByCollection")
}

// SetCreatedByCollection updates the minting auth record collection id.
func (m *FileToken) SetCreatedByCollection(collectionId string) {
	m.Set("createdByCollection", collectionId)
}

// CreatedBy returns the id of the auth record on whose behalf the URL was minted.
func (m *FileToken) CreatedBy() string {
	return m.GetString("createdBy")
}

// SetCreatedBy updates the minting auth record id.
func (m *FileToken) SetCreatedBy(recordId string) {
	m.Set("createdBy", recordId)
}

// ExpiresAt returns the token expiration time.
func (m *FileToken) ExpiresAt() types.DateTime {
	return m.GetDateTime("expiresAt")
}

// SetExpiresAt updates the token expiration time.
func (m *FileToken) SetExpiresAt(dt types.DateTime) {
	m.Set("expiresAt", dt)
}

// HasExpired reports whether the token is past its expiration.
//
// The same [DownloadTokenLeeway] clock skew tolerance from the
// signature verification is applied here as well.
func (m *FileToken) HasExpired() bool {
	exp := m.ExpiresAt().Time()
	return !exp.IsZero() && time.Now().After(exp.Add(DownloadTokenLeeway))
}

func normalizeFileTokenDisposition(disposition string) string {
	switch disposition {
	case FileTokenDispositionInline, FileTokenDispositionAttachment:
		return disposition
	default:
		return FileTokenDispositionAuto
	}
}
