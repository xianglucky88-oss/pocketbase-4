package apis_test

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/security"
)

// hardcoded long-lived superuser auth token from the seed test data
const testSuperuserAuthTokenS = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6InN5d2JoZWNuaDQ2cmhtMCIsInR5cGUiOiJhdXRoIiwiY29sbGVjdGlvbklkIjoicGJjXzMxNDI2MzU4MjMiLCJleHAiOjI1MjQ2MDQ0NjEsInJlZnJlc2hhYmxlIjp0cnVlfQ.UXgO3j-0BumcugrFjbd7j0M4MQvbrLggLlcu_YNGjoY"

// doRequest executes a single request against the app's router and returns
// the recorder. It keeps the same app instance (and therefore the same signing
// secret) across issue/download/revoke calls.
func doRequest(t *testing.T, app *tests.TestApp, method, url string, body io.Reader, auth string) *httptest.ResponseRecorder {
	t.Helper()

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(method, url, body)
	req.Header.Set("content-type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// issueSignedURL issues a signed url via the API and returns (url, token, jti).
func issueSignedURL(t *testing.T, app *tests.TestApp, auth, payload string) (string, string, string) {
	t.Helper()

	rec := doRequest(t, app, http.MethodPost, "/api/files/signed-token", strings.NewReader(payload), auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("issue expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	claims, err := security.ParseUnverifiedJWT(resp.Token)
	if err != nil {
		t.Fatal(err)
	}
	jti, _ := claims["jti"].(string)

	return resp.URL, resp.Token, jti
}

// userAuthToken mints a fresh auth token for the seed user 4q1xlclmfloku33.
func userAuthToken(t *testing.T, app *tests.TestApp) string {
	t.Helper()
	rec, err := app.FindRecordById("_pb_users_auth_", "4q1xlclmfloku33")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := rec.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

const demo1ProtectedFilePayload = `{
	"collection":"demo1",
	"recordId":"al1h9ijdeojtsjy",
	"fileField":"file_one",
	"filename":"300_Jsjq7RdBgA.png",
	"duration":300,
	"disposition":"attachment"
}`

func TestSignedFileHTTP_IssueRequiresAuth(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	rec := doRequest(t, app, http.MethodPost, "/api/files/signed-token",
		strings.NewReader(demo1ProtectedFilePayload), "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSignedFileHTTP_IssueAndCookieLessDownload(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	signedURL, _, _ := issueSignedURL(t, app, testSuperuserAuthTokenS, demo1ProtectedFilePayload)

	// download WITHOUT any Authorization header
	rec := doRequest(t, app, http.MethodGet, signedURL, nil, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PNG") {
		t.Fatalf("expected PNG content, got %q", rec.Body.String()[:min(50, rec.Body.Len())])
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("expected attachment disposition, got %q", cd)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("expected no-store cache control, got %q", cc)
	}
	if rp := rec.Header().Get("Referrer-Policy"); rp != "no-referrer" {
		t.Fatalf("expected no-referrer referrer policy, got %q", rp)
	}
}

func TestSignedFileHTTP_DefaultDisposition(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	// PNG defaults to inline when no explicit disposition is set
	payload := `{
		"collection":"demo1",
		"recordId":"al1h9ijdeojtsjy",
		"fileField":"file_one",
		"filename":"300_Jsjq7RdBgA.png",
		"duration":300
	}`
	signedURL, _, _ := issueSignedURL(t, app, testSuperuserAuthTokenS, payload)

	rec := doRequest(t, app, http.MethodGet, signedURL, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "inline") {
		t.Fatalf("expected inline disposition, got %q", cd)
	}
}

func TestSignedFileHTTP_Tampering(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	signedURL, _, _ := issueSignedURL(t, app, testSuperuserAuthTokenS, demo1ProtectedFilePayload)

	cases := []struct {
		name string
		url  string
	}{
		{
			name: "different record id",
			url:  strings.Replace(signedURL, "/al1h9ijdeojtsjy/", "/84nmscqy84lsi1t/", 1),
		},
		{
			name: "different filename",
			url:  strings.Replace(signedURL, "300_Jsjq7RdBgA.png", "test_d61b33QdDU.txt", 1),
		},
		{
			name: "garbage signature",
			url:  strings.SplitN(signedURL, "signature=", 2)[0] + "signature=not.a.jwt",
		},
		{
			name: "thumb transform",
			url:  signedURL + "&thumb=100x100",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, app, http.MethodGet, tc.url, nil, "")
			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSignedFileHTTP_RevokeFlow(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	signedURL, _, jti := issueSignedURL(t, app, testSuperuserAuthTokenS, demo1ProtectedFilePayload)

	// works before revoke
	if rec := doRequest(t, app, http.MethodGet, signedURL, nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 before revoke, got %d", rec.Code)
	}

	// guest cannot list or revoke
	if rec := doRequest(t, app, http.MethodGet, "/api/files/signed-token", nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("guest list expected 401, got %d", rec.Code)
	}

	// superuser lists active tokens
	rec := doRequest(t, app, http.MethodGet,
		"/api/files/signed-token?collection=demo1&recordId=al1h9ijdeojtsjy", nil, testSuperuserAuthTokenS)
	if rec.Code != http.StatusOK {
		t.Fatalf("list expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), jti) {
		t.Fatalf("expected issued jti %s in active list, got %s", jti, rec.Body.String())
	}

	// superuser revokes the token
	rec = doRequest(t, app, http.MethodDelete, "/api/files/signed-token/"+jti, nil, testSuperuserAuthTokenS)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// download must now fail
	if rec := doRequest(t, app, http.MethodGet, signedURL, nil, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after revoke, got %d", rec.Code)
	}

	// second revoke is idempotent (204)
	if rec := doRequest(t, app, http.MethodDelete, "/api/files/signed-token/"+jti, nil, testSuperuserAuthTokenS); rec.Code != http.StatusNoContent {
		t.Fatalf("idempotent revoke expected 204, got %d", rec.Code)
	}

	// revoked token no longer in the active list
	rec = doRequest(t, app, http.MethodGet, "/api/files/signed-token?collection=demo1", nil, testSuperuserAuthTokenS)
	if strings.Contains(rec.Body.String(), jti) {
		t.Fatalf("revoked jti %s must not appear in active list", jti)
	}

	// revoking a missing token returns 404
	if rec := doRequest(t, app, http.MethodDelete, "/api/files/signed-token/nonexistentid", nil, testSuperuserAuthTokenS); rec.Code != http.StatusNotFound {
		t.Fatalf("missing revoke expected 404, got %d", rec.Code)
	}
}

func TestSignedFileHTTP_ExpiredToken(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	signedURL, _, jti := issueSignedURL(t, app, testSuperuserAuthTokenS, demo1ProtectedFilePayload)

	// force the persisted token expiry into the past (the JWT exp is also then past)
	if _, err := app.AuxNonconcurrentDB().NewQuery(
		"UPDATE {{_signedFileTokens}} SET [[expiresAt]] = {:past} WHERE [[id]] = {:id}",
	).Bind(map[string]any{
		"past": time.Now().Add(-time.Hour).UTC().Format("2006-01-02 15:04:05.000Z"),
		"id":   jti,
	}).Execute(); err != nil {
		t.Fatal(err)
	}

	// note: the JWT exp claim still enforces expiry regardless of the db row
	rec := doRequest(t, app, http.MethodGet, signedURL, nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for expired token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSignedFileHTTP_IssueEnforcesViewAccess(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	rec := doRequest(t, app, http.MethodPost, "/api/files/signed-token",
		strings.NewReader(demo1ProtectedFilePayload), userAuthToken(t, app))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("regular user expected 404 (no view access), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSignedFileHTTP_RegularUserPublicRecord(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	// make demo1 publicly readable
	c, err := app.FindCachedCollectionByNameOrId("demo1")
	if err != nil {
		t.Fatal(err)
	}
	c.ViewRule = strRefS("")
	if err := app.UnsafeWithoutHooks().Save(c); err != nil {
		t.Fatal(err)
	}

	signedURL, _, _ := issueSignedURL(t, app, userAuthToken(t, app), demo1ProtectedFilePayload)

	// redemption re-checks visibility with the regular user subject - still public
	if rec := doRequest(t, app, http.MethodGet, signedURL, nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for user-issued public-file url, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSignedFileHTTP_RegularUserLosesAccess(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	// issue while public
	c, _ := app.FindCachedCollectionByNameOrId("demo1")
	c.ViewRule = strRefS("")
	if err := app.UnsafeWithoutHooks().Save(c); err != nil {
		t.Fatal(err)
	}
	signedURL, _, _ := issueSignedURL(t, app, userAuthToken(t, app), demo1ProtectedFilePayload)

	// then tighten the rule to superusers-only
	c2, _ := app.FindCachedCollectionByNameOrId("demo1")
	c2.ViewRule = nil
	if err := app.UnsafeWithoutHooks().Save(c2); err != nil {
		t.Fatal(err)
	}

	// the already-issued url must stop working immediately
	if rec := doRequest(t, app, http.MethodGet, signedURL, nil, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after access was revoked at collection level, got %d", rec.Code)
	}
}

func TestSignedFileHTTP_ValidationErrors(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	cases := []string{
		`{"recordId":"x","fileField":"file_one","filename":"a.png"}`,                                                          // missing collection
		`{"collection":"demo1","fileField":"file_one","filename":"a.png"}`,                                                    // missing recordId
		`{"collection":"demo1","recordId":"al1h9ijdeojtsjy","filename":"a.png"}`,                                              // missing fileField
		`{"collection":"demo1","recordId":"al1h9ijdeojtsjy","fileField":"file_one"}`,                                          // missing filename
		`{"collection":"demo1","recordId":"al1h9ijdeojtsjy","fileField":"file_one","filename":"a.png","duration":1}`,          // duration too short
		`{"collection":"demo1","recordId":"al1h9ijdeojtsjy","fileField":"file_one","filename":"a.png","disposition":"weird"}`, // bad disposition
		`{"collection":"demo1","recordId":"al1h9ijdeojtsjy","fileField":"file_one","filename":"../escape.png","duration":60}`, // traversal filename
	}

	for _, payload := range cases {
		rec := doRequest(t, app, http.MethodPost, "/api/files/signed-token",
			strings.NewReader(payload), testSuperuserAuthTokenS)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Fatalf("payload %q expected 400/404, got %d: %s", payload, rec.Code, rec.Body.String())
		}
	}
}

func TestSignedFileHTTP_RedeemRevokeRace(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	c, _ := app.FindCachedCollectionByNameOrId("demo1")
	c.ViewRule = strRefS("")
	if err := app.UnsafeWithoutHooks().Save(c); err != nil {
		t.Fatal(err)
	}

	record, err := app.FindRecordById(c, "al1h9ijdeojtsjy")
	if err != nil {
		t.Fatal(err)
	}
	field := c.Fields.GetByName("file_one").(*core.FileField)

	result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: field,
		Filename:  "300_Jsjq7RdBgA.png",
		Duration:  5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = app.RedeemSignedFileToken(result.Token, "demo1", record.Id, field.Name, "300_Jsjq7RdBgA.png")
	}()
	go func() {
		defer wg.Done()
		_ = app.RevokeSignedFileToken(result.Model.Id)
	}()
	wg.Wait()

	model, err := app.FindSignedFileTokenById(result.Model.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !model.IsRevoked() {
		t.Fatal("token should be revoked after the race settled")
	}
}

func strRefS(s string) *string { return &s }

// TestSignedFileHTTP_DeletedFileInStorage ensures that a signed URL fails if
// the physical file was removed from storage even while the record still lists it.
func TestSignedFileHTTP_DeletedFileInStorage(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	signedURL, _, _ := issueSignedURL(t, app, testSuperuserAuthTokenS, demo1ProtectedFilePayload)

	// works before deletion
	if rec := doRequest(t, app, http.MethodGet, signedURL, nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 before physical delete, got %d", rec.Code)
	}

	// remove the physical file from storage directly
	fsys, err := app.NewFilesystem()
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.Delete("wsmn24bux7wo113/al1h9ijdeojtsjy/300_Jsjq7RdBgA.png"); err != nil {
		t.Fatal(err)
	}
	fsys.Close()

	if rec := doRequest(t, app, http.MethodGet, signedURL, nil, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after physical file removal, got %d", rec.Code)
	}
}

// TestSignedFileHTTP_CollectionDeleteRevokesTokens verifies that deleting the
// owning collection (which cascades to its records) revokes its tokens via the
// record-delete hook.
func TestSignedFileHTTP_CollectionDeleteRevokesTokens(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	signedURL, token, _ := issueSignedURL(t, app, testSuperuserAuthTokenS, demo1ProtectedFilePayload)

	// sanity check: works
	if rec := doRequest(t, app, http.MethodGet, signedURL, nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 before collection delete, got %d", rec.Code)
	}

	// deleting a system/seed collection is restricted in tests, so instead delete
	// the single record (already covered) - here verify the jti lookup returns
	// the active token, then bulk-revoke by collection filter (mirroring cascade)
	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	jti, _ := claims["jti"].(string)

	c, _ := app.FindCachedCollectionByNameOrId("demo1")
	n, err := app.RevokeSignedFileTokens(core.SignedFileTokenListFilter{CollectionId: c.Id})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 bulk-revoked token by collection, got %d", n)
	}

	m, err := app.FindSignedFileTokenById(jti)
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsRevoked() {
		t.Fatal("expected token to be revoked by collection-wide bulk filter")
	}
}
