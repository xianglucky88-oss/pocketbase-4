package apis_test

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/types"
)

const (
	// superuser test fixture auth token (see file_test.go)
	testSuperuserAuthHeader = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6InN5d2JoZWNuaDQ2cmhtMCIsInR5cGUiOiJhdXRoIiwiY29sbGVjdGlvbklkIjoicGJjXzMxNDI2MzU4MjMiLCJleHAiOjI1MjQ2MDQ0NjEsInJlZnJlc2hhYmxlIjp0cnVlfQ.UXgO3j-0BumcugrFjbd7j0M4MQvbrLggLlcu_YNGjoY"
	// regular user (4q1xlclmfloku33) auth token
	testUserAuthHeader = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjRxMXhsY2xtZmxva3UzMyIsInR5cGUiOiJhdXRoIiwiY29sbGVjdGlvbklkIjoiX3BiX3VzZXJzX2F1dGhfIiwiZXhwIjoyNTI0NjA0NDYxLCJyZWZyZXNoYWJsZSI6dHJ1ZX0.ZT3F0Z3iM-xbGgSG3LEKiEzHrPHr8t8IuHLZGGNuxLo"
)

func setupFileLinkTestApp(t *testing.T) *tests.TestApp {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)
	return app
}

func doFileLinkRequest(t *testing.T, app *tests.TestApp, method string, url string, body any, authHeader string) (int, map[string]any) {
	t.Helper()

	var reqBody *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reqBody = bytes.NewReader(raw)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, url, reqBody)
	req.Header.Set("content-type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	result := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &result)
	}

	return rec.Code, result
}

func mintFileLink(t *testing.T, app *tests.TestApp, body map[string]any, authHeader string) map[string]any {
	t.Helper()

	status, result := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", body, authHeader)
	if status != http.StatusOK {
		t.Fatalf("expected mint status 200, got %d: %v", status, result)
	}

	return result
}

// -----------------------------------------------------------------------

func TestFileLinkMint(t *testing.T) {
	t.Parallel()

	t.Run("guest cannot mint", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		status, _ := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
		}, "")

		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", status)
		}
	})

	t.Run("superuser can mint and response doesn't leak secrets", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		result := mintFileLink(t, app, map[string]any{
			"collection":  "demo1",
			"record":      "al1h9ijdeojtsjy",
			"file":        "300_Jsjq7RdBgA.png",
			"duration":    300,
			"disposition": "attachment",
		}, testSuperuserAuthHeader)

		url, _ := result["url"].(string)
		if !strings.Contains(url, "token=") {
			t.Fatalf("expected url with token, got %q", url)
		}
		if !strings.Contains(url, "/api/files/demo1/al1h9ijdeojtsjy/300_Jsjq7RdBgA.png") {
			t.Fatalf("unexpected url %q", url)
		}
		if result["disposition"] != "attachment" {
			t.Fatalf("expected attachment disposition, got %v", result["disposition"])
		}
		if result["expiresAt"] == "" {
			t.Fatal("expected expiresAt to be set")
		}

		// must not leak storage key/material
		raw, _ := json.Marshal(result)
		s := string(raw)
		if strings.Contains(s, "wsmn24bux7wo113") {
			t.Fatalf("response leaks the raw storage key: %s", s)
		}
	})

	t.Run("non-authorized user cannot mint for protected record", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		// demo1's default ViewRule denies the regular test user
		status, _ := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
		}, testUserAuthHeader)

		if status != http.StatusNotFound {
			t.Fatalf("expected 404 for unauthorized mint, got %d", status)
		}
	})

	t.Run("authorized user can mint when ViewRule allows it", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		c, err := app.FindCachedCollectionByNameOrId("demo1")
		if err != nil {
			t.Fatal(err)
		}
		c.ViewRule = types.Pointer("@request.auth.id != ''")
		if err := app.UnsafeWithoutHooks().Save(c); err != nil {
			t.Fatal(err)
		}

		status, result := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   120,
		}, testUserAuthHeader)

		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %v", status, result)
		}
	})

	t.Run("mint validates duration and disposition", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		base := map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
		}

		base["duration"] = 30
		if status, _ := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", base, testSuperuserAuthHeader); status != http.StatusBadRequest {
			t.Fatalf("expected 400 for duration < 1min, got %d", status)
		}

		base["duration"] = 999999
		if status, _ := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", base, testSuperuserAuthHeader); status != http.StatusBadRequest {
			t.Fatalf("expected 400 for duration > 7days, got %d", status)
		}

		base["duration"] = 300
		base["disposition"] = "weird"
		if status, _ := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", base, testSuperuserAuthHeader); status != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid disposition, got %d", status)
		}
	})

	t.Run("mint rejects nonexistent and renamed files", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		body := map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "renamed_or_missing.png",
			"duration":   300,
		}
		status, _ := doFileLinkRequest(t, app, http.MethodPost, "/api/files/links", body, testSuperuserAuthHeader)
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing file, got %d", status)
		}
	})
}

func TestFileLinkSignedDownload(t *testing.T) {
	t.Parallel()

	newSignedURL := func(t *testing.T, app *tests.TestApp, disposition string) string {
		result := mintFileLink(t, app, map[string]any{
			"collection":  "demo1",
			"record":      "al1h9ijdeojtsjy",
			"file":        "300_Jsjq7RdBgA.png",
			"duration":    300,
			"disposition": disposition,
		}, testSuperuserAuthHeader)
		u, _ := result["url"].(string)
		return u
	}

	t.Run("valid signed URL downloads the file without cookies", func(t *testing.T) {
		app := setupFileLinkTestApp(t)
		u := newSignedURL(t, app, "auto")

		status, result := doFileLinkRequest(t, app, http.MethodGet, u, nil, "")
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %v", status, result)
		}

		// doFileLinkRequest unmarshals to map (works for json, binary fails silently);
		// do a raw request to verify body
		req := httptest.NewRequest(http.MethodGet, u, nil)
		router, _ := apis.NewRouter(app)
		mux, _ := router.BuildMux()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected raw 200, got %d", rec.Code)
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("PNG")) {
			t.Fatal("expected PNG content")
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Fatalf("expected private no-store cache control, got %q", cc)
		}
	})

	t.Run("signed disposition cannot be upgraded by query params", func(t *testing.T) {
		app := setupFileLinkTestApp(t)
		u := newSignedURL(t, app, "auto")

		// PNGs are served inline by default; try to force attachment
		req := httptest.NewRequest(http.MethodGet, u+"&download=true", nil)
		router, _ := apis.NewRouter(app)
		mux, _ := router.BuildMux()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		cd := rec.Header().Get("Content-Disposition")
		if !strings.HasPrefix(cd, "inline") {
			t.Fatalf("expected inline disposition to stay inline, got %q", cd)
		}

		// explicit attachment claim is honored
		uAttach := newSignedURL(t, app, "attachment")
		req2 := httptest.NewRequest(http.MethodGet, uAttach, nil)
		router2, _ := apis.NewRouter(app)
		mux2, _ := router2.BuildMux()
		rec2 := httptest.NewRecorder()
		mux2.ServeHTTP(rec2, req2)
		if cd2 := rec2.Header().Get("Content-Disposition"); !strings.HasPrefix(cd2, "attachment") {
			t.Fatalf("expected attachment disposition, got %q", cd2)
		}
	})

	t.Run("tampered record id in URL is rejected", func(t *testing.T) {
		app := setupFileLinkTestApp(t)
		u := newSignedURL(t, app, "auto")

		tampered := strings.Replace(u, "al1h9ijdeojtsjy", "4q1xlclmfloku33", 1)
		status, _ := doFileLinkRequest(t, app, http.MethodGet, tampered, nil, "")
		if status != http.StatusNotFound {
			t.Fatalf("expected 404 for tampered record, got %d", status)
		}
	})

	t.Run("tampered filename in URL is rejected", func(t *testing.T) {
		app := setupFileLinkTestApp(t)
		u := newSignedURL(t, app, "auto")

		tampered := strings.Replace(u, "300_Jsjq7RdBgA.png", "300_1SEi6Q6U72.png", 1)
		status, _ := doFileLinkRequest(t, app, http.MethodGet, tampered, nil, "")
		if status != http.StatusNotFound {
			t.Fatalf("expected 404 for tampered filename, got %d", status)
		}
	})

	t.Run("tampered signature is rejected", func(t *testing.T) {
		app := setupFileLinkTestApp(t)
		u := newSignedURL(t, app, "auto")

		// flip a character in the middle of the JWT signature segment
		// (the third dot-delimited part), which invalidates the HMAC
		tokenStart := strings.Index(u, "token=") + len("token=")
		token := u[tokenStart:]
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT parts, got %d", len(parts))
		}
		mid := len(parts[2]) / 2
		b := []byte(parts[2])
		if b[mid] == 'A' {
			b[mid] = 'B'
		} else {
			b[mid] = 'A'
		}
		parts[2] = string(b)
		tampered := u[:tokenStart] + strings.Join(parts, ".")

		status, _ := doFileLinkRequest(t, app, http.MethodGet, tampered, nil, "")
		if status != http.StatusNotFound {
			t.Fatalf("expected 404 for tampered signature, got %d", status)
		}
	})

	t.Run("token from a different collection cannot be replayed", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		// sign using the user (4q1...) for its own public file, then replay against demo1
		u := newSignedURL(t, app, "auto")

		// mangle just the path prefix while keeping the token - mismatch must be rejected
		tampered := strings.Replace(u, "/api/files/demo1/", "/api/files/_pb_users_auth_/", 1)
		status, _ := doFileLinkRequest(t, app, http.MethodGet, tampered, nil, "")
		if status != http.StatusNotFound {
			t.Fatalf("expected 404 when replaying token on another collection, got %d", status)
		}
	})

	t.Run("expired token is rejected even with clock skew leeway", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		record, err := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
		if err != nil {
			t.Fatal(err)
		}

		su, err := app.FindRecordById(core.CollectionNameSuperusers, "sywbhecnh46rhm0")
		if err != nil {
			t.Fatal(err)
		}

		// sign a token that expired 5 minutes ago (well beyond the 60s leeway)
		token, id, err := su.NewFileDownloadToken(record, "file_one", "300_Jsjq7RdBgA.png", "auto", -5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		model := core.NewFileToken(app)
		model.MarkAsNew()
		model.Id = id
		model.SetCollectionRef(record.Collection().Id)
		model.SetRecordRef(record.Id)
		model.SetFileField("file_one")
		model.SetFilename("300_Jsjq7RdBgA.png")
		model.SetDisposition("auto")
		model.SetCreatedByCollection(su.Collection().Id)
		model.SetCreatedBy(su.Id)
		model.SetExpiresAt(types.NowDateTime().Add(-5 * time.Minute))
		if err := app.Save(model); err != nil {
			t.Fatal(err)
		}

		u := "/api/files/demo1/al1h9ijdeojtsjy/300_Jsjq7RdBgA.png?token=" + token
		status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, "")
		if status != http.StatusNotFound {
			t.Fatalf("expected 404 for expired token, got %d", status)
		}
	})

	t.Run("token within the clock skew leeway is accepted", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		record, err := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
		if err != nil {
			t.Fatal(err)
		}
		su, err := app.FindRecordById(core.CollectionNameSuperusers, "sywbhecnh46rhm0")
		if err != nil {
			t.Fatal(err)
		}

		// expired 10s ago - inside the DownloadTokenLeeway (60s)
		token, id, err := su.NewFileDownloadToken(record, "file_one", "300_Jsjq7RdBgA.png", "auto", -10*time.Second)
		if err != nil {
			t.Fatal(err)
		}

		model := core.NewFileToken(app)
		model.MarkAsNew()
		model.Id = id
		model.SetCollectionRef(record.Collection().Id)
		model.SetRecordRef(record.Id)
		model.SetFileField("file_one")
		model.SetFilename("300_Jsjq7RdBgA.png")
		model.SetDisposition("auto")
		model.SetCreatedByCollection(su.Collection().Id)
		model.SetCreatedBy(su.Id)
		model.SetExpiresAt(types.NowDateTime().Add(5 * time.Minute)) // row still present
		if err := app.Save(model); err != nil {
			t.Fatal(err)
		}

		u := "/api/files/demo1/al1h9ijdeojtsjy/300_Jsjq7RdBgA.png?token=" + token
		status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, "")
		if status != http.StatusOK {
			t.Fatalf("expected 200 inside leeway, got %d", status)
		}
	})

	t.Run("legacy file token cannot bypass revocation model", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		// mint a legacy, non-revocable file token via the regular endpoint
		status, result := doFileLinkRequest(t, app, http.MethodPost, "/api/files/token", nil, testSuperuserAuthHeader)
		if status != http.StatusOK {
			t.Fatalf("expected legacy token 200, got %d", status)
		}
		legacyToken, _ := result["token"].(string)

		// replaying it as-is still follows the legacy rule path (works for superuser)
		u := "/api/files/demo1/al1h9ijdeojtsjy/300_Jsjq7RdBgA.png?token=" + legacyToken
		if code, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); code != http.StatusOK {
			t.Fatalf("expected legacy token to work on its own path, got %d", code)
		}

		// there must be no _fileTokens row created for legacy tokens
		if total, _ := app.CountRecords(core.CollectionNameFileTokens); total != 0 {
			t.Fatalf("expected no revocation rows for legacy file tokens, got %d", total)
		}
	})

	t.Run("signed token requires a backing revocation row even with valid signature", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		record, _ := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
		su, _ := app.FindRecordById(core.CollectionNameSuperusers, "sywbhecnh46rhm0")

		token, _, err := su.NewFileDownloadToken(record, "file_one", "300_Jsjq7RdBgA.png", "auto", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		// deliberately do NOT persist the FileToken row

		u := "/api/files/demo1/al1h9ijdeojtsjy/300_Jsjq7RdBgA.png?token=" + token
		if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusNotFound {
			t.Fatalf("expected 404 without backing revocation row, got %d", status)
		}
	})

	t.Run("thumb param is ignored for signed URLs", func(t *testing.T) {
		app := setupFileLinkTestApp(t)
		u := newSignedURL(t, app, "auto")

		req := httptest.NewRequest(http.MethodGet, u+"&thumb=100x100", nil)
		router, _ := apis.NewRouter(app)
		mux, _ := router.BuildMux()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if strings.Contains(rec.Header().Get("Content-Disposition"), "100x100_") {
			t.Fatal("signed URL should not serve thumb variants")
		}
	})
}

func TestFileLinkRevocation(t *testing.T) {
	t.Parallel()

	t.Run("revoke by id and download is rejected afterwards", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		result := mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testSuperuserAuthHeader)

		id, _ := result["id"].(string)
		u, _ := result["url"].(string)

		if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusOK {
			t.Fatalf("expected working URL before revoke, got %d", status)
		}

		if status, _ := doFileLinkRequest(t, app, http.MethodDelete, "/api/files/links/"+id, nil, testSuperuserAuthHeader); status != http.StatusNoContent {
			t.Fatalf("expected 204 on revoke, got %d", status)
		}

		if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusNotFound {
			t.Fatalf("expected 404 after revoke, got %d", status)
		}

		// revoking again is an idempotent no-op
		if status, _ := doFileLinkRequest(t, app, http.MethodDelete, "/api/files/links/"+id, nil, testSuperuserAuthHeader); status != http.StatusNoContent {
			t.Fatalf("expected 204 on double revoke, got %d", status)
		}
	})

	t.Run("non-creator cannot revoke", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		// let the regular user mint a link first
		c, err := app.FindCachedCollectionByNameOrId("demo1")
		if err != nil {
			t.Fatal(err)
		}
		c.ViewRule = types.Pointer("@request.auth.id != ''")
		if err := app.UnsafeWithoutHooks().Save(c); err != nil {
			t.Fatal(err)
		}

		result := mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testUserAuthHeader)
		id, _ := result["id"].(string)
		u, _ := result["url"].(string)

		// the user's own URL works
		if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusOK {
			t.Fatalf("expected 200 for creator URL, got %d", status)
		}

		// mint a second link as superuser and ensure the regular user can't revoke it
		other := mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testSuperuserAuthHeader)
		otherID, _ := other["id"].(string)

		if status, _ := doFileLinkRequest(t, app, http.MethodDelete, "/api/files/links/"+otherID, nil, testUserAuthHeader); status != http.StatusNotFound {
			t.Fatalf("expected 404 when non-creator revokes, got %d", status)
		}

		// the superuser-minted link must still work
		if status, _ := doFileLinkRequest(t, app, http.MethodGet, other["url"].(string), nil, ""); status != http.StatusOK {
			t.Fatalf("expected superuser link to remain valid, got %d", status)
		}

		// creator can revoke own link
		if status, _ := doFileLinkRequest(t, app, http.MethodDelete, "/api/files/links/"+id, nil, testUserAuthHeader); status != http.StatusNoContent {
			t.Fatalf("expected 204 for creator revoke, got %d", status)
		}
	})

	t.Run("concurrent revoke racing with downloads", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		result := mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testSuperuserAuthHeader)
		id, _ := result["id"].(string)
		u, _ := result["url"].(string)

		var wg sync.WaitGroup
		var okAfter, revoked int64
		var mu sync.Mutex

		// hammer downloads while a revoke happens in the middle
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if i == 10 {
					doFileLinkRequest(t, app, http.MethodDelete, "/api/files/links/"+id, nil, testSuperuserAuthHeader)
				}
				status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, "")
				mu.Lock()
				if status == http.StatusOK {
					okAfter++
				} else if status == http.StatusNotFound {
					revoked++
				}
				mu.Unlock()
			}(i)
		}
		wg.Wait()

		if okAfter+revoked != 20 {
			t.Fatalf("expected all 20 requests to resolve as 200/404, got ok=%d revoked=%d", okAfter, revoked)
		}
		if revoked == 0 {
			t.Fatal("expected at least one request after the revoke to be rejected")
		}
	})

	t.Run("target record delete cascades and revokes all links", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testSuperuserAuthHeader)

		rows, err := app.FindAllFileTokensByTargetRecord(func() *core.Record {
			r, _ := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
			return r
		}())
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("expected 1 file token row, got %d", len(rows))
		}

		// deleting the target record cascades to its file token rows
		record, err := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
		if err != nil {
			t.Fatal(err)
		}
		if err := app.Delete(record); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindFileTokenById(rows[0].Id); err == nil {
			t.Fatal("expected token row to be cascade-deleted with the target record")
		}
	})
}

func TestFileLinkVisibilityRecheck(t *testing.T) {
	t.Parallel()

	t.Run("revoking view access after mint invalidates the URL", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		// initially allow any auth user
		c, err := app.FindCachedCollectionByNameOrId("demo1")
		if err != nil {
			t.Fatal(err)
		}
		c.ViewRule = types.Pointer("@request.auth.id != ''")
		if err := app.UnsafeWithoutHooks().Save(c); err != nil {
			t.Fatal(err)
		}

		result := mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testUserAuthHeader)
		u, _ := result["url"].(string)

		if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusOK {
			t.Fatalf("expected 200 while access allowed, got %d", status)
		}

		// tighten the rule after the URL was already shared
		c, _ = app.FindCachedCollectionByNameOrId("demo1")
		c.ViewRule = types.Pointer("@request.auth.verified = true")
		if err := app.UnsafeWithoutHooks().Save(c); err != nil {
			t.Fatal(err)
		}

		if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusNotFound {
			t.Fatalf("expected 404 after access was revoked, got %d", status)
		}
	})
}

func TestFileLinkList(t *testing.T) {
	t.Parallel()

	t.Run("superuser lists and creator filter applies", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		c, _ := app.FindCachedCollectionByNameOrId("demo1")
		c.ViewRule = types.Pointer("@request.auth.id != ''")
		if err := app.UnsafeWithoutHooks().Save(c); err != nil {
			t.Fatal(err)
		}

		mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testUserAuthHeader)
		mintFileLink(t, app, map[string]any{
			"collection": "demo1",
			"record":     "al1h9ijdeojtsjy",
			"file":       "300_Jsjq7RdBgA.png",
			"duration":   300,
		}, testSuperuserAuthHeader)

		// superuser sees both
		status, result := doFileLinkRequest(t, app, http.MethodGet,
			"/api/files/links?collection=demo1&record=al1h9ijdeojtsjy", nil, testSuperuserAuthHeader)
		if status != http.StatusOK {
			t.Fatalf("expected 200 list, got %d", status)
		}
		items, _ := result["items"].([]any)
		if len(items) != 2 {
			t.Fatalf("expected 2 links for superuser, got %d", len(items))
		}

		// list responses must never embed the long-lived token itself
		raw, _ := json.Marshal(result)
		if strings.Contains(string(raw), "Bearer") {
			t.Fatal("list response leaks credentials")
		}

		// regular user sees only its own
		status2, result2 := doFileLinkRequest(t, app, http.MethodGet,
			"/api/files/links?collection=demo1&record=al1h9ijdeojtsjy", nil, testUserAuthHeader)
		if status2 != http.StatusOK {
			t.Fatalf("expected 200 list for user, got %d", status2)
		}
		items2, _ := result2["items"].([]any)
		if len(items2) != 1 {
			t.Fatalf("expected 1 own link for regular user, got %d", len(items2))
		}
	})
}

func TestFileLinkRenameBehavior(t *testing.T) {
	t.Parallel()

	app := setupFileLinkTestApp(t)

	record, err := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
	if err != nil {
		t.Fatal(err)
	}

	result := mintFileLink(t, app, map[string]any{
		"collection": "demo1",
		"record":     record.Id,
		"file":       "300_Jsjq7RdBgA.png",
		"duration":   300,
	}, testSuperuserAuthHeader)
	u, _ := result["url"].(string)

	if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusOK {
		t.Fatalf("expected 200 before rename, got %d", status)
	}

	// simulate a rename: build a reuploadable file from the stored object
	// under a new (random-suffixed) name and replace the field value
	fsys, err := app.NewFilesystem()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsys.Close() })

	oldKey := record.BaseFilesPath() + "/300_Jsjq7RdBgA.png"
	newFile, err := fsys.GetReuploadableFile(oldKey, false)
	if err != nil {
		t.Fatal(err)
	}
	newName := newFile.Name
	if newName == "300_Jsjq7RdBgA.png" {
		t.Fatalf("expected a new randomized file name, got %s", newName)
	}

	record.Set("file_one", newFile)
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}

	// the old object must have been removed during the field cleanup
	if exists, _ := fsys.Exists(oldKey); exists {
		t.Fatal("expected the old storage object to be deleted after rename")
	}

	// 1) the old signed URL fails (record no longer references the file AND
	// the storage object is gone - re-checked right before reading)
	if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusNotFound {
		t.Fatalf("expected 404 for renamed-away file, got %d", status)
	}

	// 2) the orphaned row is revoked automatically by the record update hook
	if total, _ := app.CountRecords(core.CollectionNameFileTokens); total != 0 {
		t.Fatalf("expected stale file token rows to be cleaned up on rename, got %d", total)
	}

	// and the old signed URL keeps failing afterwards
	if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusNotFound {
		t.Fatalf("expected persistent 404 for the renamed-away file, got %d", status)
	}

	// 3) a new link for the renamed file works
	newResult := mintFileLink(t, app, map[string]any{
		"collection": "demo1",
		"record":     record.Id,
		"file":       newName,
		"duration":   300,
	}, testSuperuserAuthHeader)
	if status, _ := doFileLinkRequest(t, app, http.MethodGet, newResult["url"].(string), nil, ""); status != http.StatusOK {
		t.Fatalf("expected 200 for renamed file link, got %d", status)
	}
}

func TestFileLinkExpiredCleanup(t *testing.T) {
	t.Parallel()

	app := setupFileLinkTestApp(t)

	if err := app.DeleteExpiredFileTokens(); err != nil {
		t.Fatal(err)
	}

	// create an expired row directly
	record, _ := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
	su, _ := app.FindRecordById(core.CollectionNameSuperusers, "sywbhecnh46rhm0")

	model := core.NewFileToken(app)
	model.MarkAsNew()
	model.SetCollectionRef(record.Collection().Id)
	model.SetRecordRef(record.Id)
	model.SetFileField("file_one")
	model.SetFilename("300_Jsjq7RdBgA.png")
	model.SetDisposition("auto")
	model.SetCreatedByCollection(su.Collection().Id)
	model.SetCreatedBy(su.Id)
	model.SetExpiresAt(types.NowDateTime().Add(-24 * time.Hour))
	if err := app.Save(model); err != nil {
		t.Fatal(err)
	}

	if err := app.DeleteExpiredFileTokens(); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindFileTokenById(model.Id); err == nil {
		t.Fatal("expected expired file token row to be cleaned up")
	}
}

func TestFileLinkTokenKeyRotationInvalidates(t *testing.T) {
	t.Parallel()

	app := setupFileLinkTestApp(t)

	c, _ := app.FindCachedCollectionByNameOrId("demo1")
	c.ViewRule = types.Pointer("@request.auth.id != ''")
	if err := app.UnsafeWithoutHooks().Save(c); err != nil {
		t.Fatal(err)
	}

	result := mintFileLink(t, app, map[string]any{
		"collection": "demo1",
		"record":     "al1h9ijdeojtsjy",
		"file":       "300_Jsjq7RdBgA.png",
		"duration":   300,
	}, testUserAuthHeader)
	u, _ := result["url"].(string)

	if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusOK {
		t.Fatalf("expected 200 before tokenKey rotation, got %d", status)
	}

	// rotate the minting user's tokenKey (eg. password change / sign out everywhere)
	user, _ := app.FindRecordById("_pb_users_auth_", "4q1xlclmfloku33")
	user.RefreshTokenKey()
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}

	if status, _ := doFileLinkRequest(t, app, http.MethodGet, u, nil, ""); status != http.StatusNotFound {
		t.Fatalf("expected 404 after tokenKey rotation, got %d", status)
	}
}

func TestFileLinkSignedURLHelpers(t *testing.T) {
	t.Parallel()

	t.Run("core signing claims roundtrip", func(t *testing.T) {
		app := setupFileLinkTestApp(t)

		target, err := app.FindRecordById("demo1", "al1h9ijdeojtsjy")
		if err != nil {
			t.Fatal(err)
		}
		su, err := app.FindRecordById(core.CollectionNameSuperusers, "sywbhecnh46rhm0")
		if err != nil {
			t.Fatal(err)
		}

		token, id, err := su.NewFileDownloadToken(target, "file_one", "300_Jsjq7RdBgA.png", "inline", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if id == "" || token == "" {
			t.Fatal("expected non-empty token and id")
		}

		// persist the backing revocation row (normally done by the mint API)
		model := core.NewFileToken(app)
		model.MarkAsNew()
		model.Id = id
		model.SetCollectionRef(target.Collection().Id)
		model.SetRecordRef(target.Id)
		model.SetFileField("file_one")
		model.SetFilename("300_Jsjq7RdBgA.png")
		model.SetDisposition("inline")
		model.SetCreatedByCollection(su.Collection().Id)
		model.SetCreatedBy(su.Id)
		model.SetExpiresAt(types.NowDateTime().Add(time.Minute))
		if err := app.Save(model); err != nil {
			t.Fatal(err)
		}

		claims, err := app.VerifyFileDownloadToken(token, target.Collection().Id, target.Id, "file_one", "300_Jsjq7RdBgA.png")
		if err != nil {
			t.Fatalf("expected verification to succeed, got %v", err)
		}
		if claims.Disposition != "inline" {
			t.Fatalf("expected inline disposition, got %s", claims.Disposition)
		}
		if claims.JTI != id {
			t.Fatalf("jti mismatch: %s vs %s", claims.JTI, id)
		}

		if _, err := app.VerifyFileDownloadToken(token, target.Collection().Id, "otherrecord", "file_one", "300_Jsjq7RdBgA.png"); err == nil {
			t.Fatal("expected verification to fail for a different record id")
		}

		// every other signed binding must mismatch as well
		wrongCases := []struct {
			collectionID string
			recordID     string
			field        string
			filename     string
		}{
			{"zzzznotacollection", target.Id, "file_one", "300_Jsjq7RdBgA.png"},      // other collection
			{target.Collection().Id, target.Id, "other_field", "300_Jsjq7RdBgA.png"}, // other field
			{target.Collection().Id, target.Id, "file_one", "other.png"},             // other file
			{target.Collection().Id, target.Id, "file_one", ""},                      // missing file
		}
		for i, c := range wrongCases {
			if _, err := app.VerifyFileDownloadToken(token, c.collectionID, c.recordID, c.field, c.filename); err == nil {
				t.Fatalf("mismatch case %d unexpectedly verified", i)
			}
		}

		// an empty token is rejected without touching the storage
		if _, err := app.VerifyFileDownloadToken("", target.Collection().Id, target.Id, "file_one", "300_Jsjq7RdBgA.png"); err == nil {
			t.Fatal("expected verification to fail for empty token")
		}

		// after revocation the jti lookup fails even though the JWT signature is still valid
		if err := app.DeleteFileToken(model); err != nil {
			t.Fatal(err)
		}
		if _, err := app.VerifyFileDownloadToken(token, target.Collection().Id, target.Id, "file_one", "300_Jsjq7RdBgA.png"); err == nil {
			t.Fatal("expected verification to fail after the revocation row was deleted")
		}
	})
}
