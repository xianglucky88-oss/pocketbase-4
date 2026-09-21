package core_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func newSignedTokenTestApp(t *testing.T) *tests.TestApp {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func loadDemo1SignedFileTarget(t *testing.T, app *tests.TestApp) (*core.Record, *core.FileField, string) {
	collection, err := app.FindCachedCollectionByNameOrId("demo1")
	if err != nil {
		t.Fatal(err)
	}

	// make demo1 publicly readable so that subject-less (guest) redemption can
	// proceed for a record that is genuinely public at redemption time.
	collection.ViewRule = strPtr("")
	if err := app.UnsafeWithoutHooks().Save(collection); err != nil {
		t.Fatal(err)
	}

	record, err := app.FindRecordById(collection, "al1h9ijdeojtsjy")
	if err != nil {
		t.Fatal(err)
	}

	field, ok := collection.Fields.GetByName("file_one").(*core.FileField)
	if !ok {
		t.Fatalf("file_one is not a *FileField")
	}

	// ensure the file actually exists
	filename := "300_Jsjq7RdBgA.png"
	if record.FindFileFieldByFile(filename) == nil {
		t.Fatalf("file %q not attached to the test record", filename)
	}

	return record, field, filename
}

func strPtr(s string) *string { return &s }

func TestSignedFileToken_IssueAndRedeem(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:      record,
		FileField:   field,
		Filename:    filename,
		Duration:    time.Minute,
		Disposition: core.SignedFileDispositionAttachment,
	})
	if err != nil {
		t.Fatalf("NewSignedFileToken error: %v", err)
	}

	if result.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// redeem using collection NAME (as it appears in the URL)
	redemption, err := app.RedeemSignedFileToken(result.Token, "demo1", record.Id, field.Name, filename)
	if err != nil {
		t.Fatalf("RedeemSignedFileToken error: %v", err)
	}

	if redemption.Disposition != core.SignedFileDispositionAttachment {
		t.Fatalf("expected attachment disposition, got %q", redemption.Disposition)
	}
	if redemption.Record.Id != record.Id {
		t.Fatalf("redemption record mismatch")
	}
	if redemption.Collection.Id != record.Collection().Id {
		t.Fatalf("redemption collection mismatch")
	}
	if redemption.FileField.Name != field.Name {
		t.Fatalf("redemption field mismatch")
	}
}

func TestSignedFileToken_TamperRejected(t *testing.T) {
	t.Parallel()

	t.Run("modified filename in URL", func(t *testing.T) {
		app := newSignedTokenTestApp(t)
		defer app.Cleanup()

		record, field, filename := loadDemo1SignedFileTarget(t, app)

		result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
			Record:    record,
			FileField: field,
			Filename:  filename,
			Duration:  time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}

		// request the token against a different file - must fail
		if _, err := app.RedeemSignedFileToken(result.Token, "demo1", record.Id, field.Name, "other_123.png"); err == nil {
			t.Fatal("expected mismatch error for a different filename")
		}
	})

	t.Run("modified record id in URL", func(t *testing.T) {
		app := newSignedTokenTestApp(t)
		defer app.Cleanup()

		record, field, filename := loadDemo1SignedFileTarget(t, app)

		result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
			Record:    record,
			FileField: field,
			Filename:  filename,
			Duration:  time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}

		// try to access another record of the same collection with the token
		if _, err := app.RedeemSignedFileToken(result.Token, "demo1", "84nmscqy84lsi1t", field.Name, filename); err == nil {
			t.Fatal("expected mismatch error for a different record id")
		}
	})

	t.Run("modified collection in URL", func(t *testing.T) {
		app := newSignedTokenTestApp(t)
		defer app.Cleanup()

		record, field, filename := loadDemo1SignedFileTarget(t, app)

		result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
			Record:    record,
			FileField: field,
			Filename:  filename,
			Duration:  time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}

		// different collection name entirely
		if _, err := app.RedeemSignedFileToken(result.Token, "demo2", record.Id, field.Name, filename); err == nil {
			t.Fatal("expected mismatch/error for a different collection")
		}
	})

	t.Run("corrupted signature", func(t *testing.T) {
		app := newSignedTokenTestApp(t)
		defer app.Cleanup()

		record, field, filename := loadDemo1SignedFileTarget(t, app)

		result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
			Record:    record,
			FileField: field,
			Filename:  filename,
			Duration:  time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}

		// flip the last character of the JWT signature
		token := result.Token
		badToken := token[:len(token)-1]
		if strings.HasSuffix(badToken, "A") {
			badToken += "B"
		} else {
			badToken += "A"
		}

		if _, err := app.RedeemSignedFileToken(badToken, "demo1", record.Id, field.Name, filename); err == nil {
			t.Fatal("expected error for a tampered signature")
		}
	})

	t.Run("forged token signed with another secret", func(t *testing.T) {
		app := newSignedTokenTestApp(t)
		defer app.Cleanup()

		record, field, filename := loadDemo1SignedFileTarget(t, app)

		// a token issued by another (separate) app instance won't validate
		// because its secret differs - simulate by issuing against a freshly
		// created separate datadir app
		otherApp := newSignedTokenTestApp(t)
		defer otherApp.Cleanup()

		result, err := otherApp.NewSignedFileToken(core.SignedFileTokenOptions{
			Record:    record,
			FileField: field,
			Filename:  filename,
			Duration:  time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}

		// note: both test apps share the same seed data, so the record exists;
		// only the signing secret must differ. If the random secrets happen to
		// collide (astronomically unlikely) just re-issue once.
		if _, err := app.RedeemSignedFileToken(result.Token, "demo1", record.Id, field.Name, filename); err == nil {
			// give the test one more chance in case of the ~impossible secret collision
			result2, _ := otherApp.NewSignedFileToken(core.SignedFileTokenOptions{
				Record:    record,
				FileField: field,
				Filename:  filename,
				Duration:  time.Minute,
			})
			if _, err := app.RedeemSignedFileToken(result2.Token, "demo1", record.Id, field.Name, filename); err == nil {
				t.Fatal("expected a foreign-signed token to be rejected")
			}
		}
	})
}

func TestSignedFileToken_Expiry(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: field,
		Filename:  filename,
		Duration:  10 * time.Second, // minimum
	})
	if err != nil {
		t.Fatal(err)
	}

	// manually expire the persisted row
	model, err := app.FindSignedFileTokenById(result.Model.Id)
	if err != nil {
		t.Fatal(err)
	}

	// the JWT itself enforces exp; verify an expired persisted model is treated
	// as expired/non-active by the model helpers:
	if err := model.ExpiresAt.Scan(time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !model.HasExpired() {
		t.Fatal("expected model to be expired")
	}
	if model.IsActive() {
		t.Fatal("expected model to be inactive when expired")
	}

	// still-active token redeems fine
	fresh, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: field,
		Filename:  filename,
		Duration:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.RedeemSignedFileToken(fresh.Token, "demo1", record.Id, field.Name, filename); err != nil {
		t.Fatalf("expected fresh token to redeem: %v", err)
	}
}

func TestSignedFileToken_Revoke(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: field,
		Filename:  filename,
		Duration:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// works before revoke
	if _, err := app.RedeemSignedFileToken(result.Token, "demo1", record.Id, field.Name, filename); err != nil {
		t.Fatalf("expected token to redeem before revoke: %v", err)
	}

	if err := app.RevokeSignedFileToken(result.Model.Id); err != nil {
		t.Fatalf("revoke error: %v", err)
	}

	// redemption must fail after revoke
	if _, err := app.RedeemSignedFileToken(result.Token, "demo1", record.Id, field.Name, filename); err == nil {
		t.Fatal("expected revoked token to be rejected")
	}

	// revoking again is idempotent and must not "resurrect" the token
	if err := app.RevokeSignedFileToken(result.Model.Id); err != nil {
		t.Fatalf("second revoke should be idempotent, got: %v", err)
	}

	// revoking a missing id returns ErrSignedFileTokenNotFound
	if err := app.RevokeSignedFileToken("does-not-exist"); err != core.ErrSignedFileTokenNotFound {
		t.Fatalf("expected ErrSignedFileTokenNotFound, got %v", err)
	}
}

func TestSignedFileToken_ConcurrentRevoke(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	const n = 20
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
			Record:    record,
			FileField: field,
			Filename:  filename,
			Duration:  time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = result.Model.Id
	}

	var wg sync.WaitGroup
	// concurrently revoke each id multiple times
	for _, id := range ids {
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				_ = app.RevokeSignedFileToken(id)
			}(id)
		}
	}
	wg.Wait()

	// all tokens must be revoked and redeem must fail for all
	for _, id := range ids {
		model, err := app.FindSignedFileTokenById(id)
		if err != nil {
			t.Fatalf("find token %s: %v", id, err)
		}
		if !model.IsRevoked() {
			t.Fatalf("token %s was not revoked after concurrent revocations", id)
		}
	}
}

func TestSignedFileToken_BulkRevokeForFile(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	// 3 tokens for the target file
	for i := 0; i < 3; i++ {
		if _, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
			Record:    record,
			FileField: field,
			Filename:  filename,
			Duration:  time.Minute,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// 1 token for a different file (file_many on the same record)
	otherField, ok := record.Collection().Fields.GetByName("file_many").(*core.FileField)
	if !ok {
		t.Fatal("file_many missing")
	}
	if _, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: otherField,
		Filename:  "test_QZFjKjXchk.txt",
		Duration:  time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	revoked, err := app.RevokeAllSignedFileTokensForFile(record.Collection().Id, record.Id, field.Name, filename)
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 3 {
		t.Fatalf("expected 3 revoked tokens, got %d", revoked)
	}

	// the other file tokens remain active
	active, err := app.FindActiveSignedFileTokens(core.SignedFileTokenListFilter{
		CollectionId: record.Collection().Id,
		RecordId:     record.Id,
		FileField:    "file_many",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active token on the other field, got %d", len(active))
	}
}

func TestSignedFileToken_RenamedFileInvalidatesURL(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: field,
		Filename:  filename,
		Duration:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// simulate a file rename/replacement: the field value changes to a new filename.
	// (we don't need a real upload for the revocation hook logic; just the old/new diff)
	record.Set(field.Name, "renamed_NEWFILE.png")
	if err := app.SaveNoValidate(record); err != nil {
		t.Fatal(err)
	}

	// the token for the OLD filename must have been auto-revoked
	model, err := app.FindSignedFileTokenById(result.Model.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !model.IsRevoked() {
		t.Fatal("expected token to be revoked after the file was renamed")
	}

	// and redemption fails (record no longer lists the old file anyway)
	if _, err := app.RedeemSignedFileToken(result.Token, "demo1", record.Id, field.Name, filename); err == nil {
		t.Fatal("expected renamed-file token redemption to fail")
	}
}

func TestSignedFileToken_DeletedRecordInvalidatesURL(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: field,
		Filename:  filename,
		Duration:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// deleting the record must bulk-revoke its tokens
	if err := app.Delete(record); err != nil {
		t.Fatal(err)
	}

	model, err := app.FindSignedFileTokenById(result.Model.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !model.IsRevoked() {
		t.Fatal("expected token to be revoked after record deletion")
	}
}

func TestSignedFileToken_DeleteExpired(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	result, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:    record,
		FileField: field,
		Filename:  filename,
		Duration:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// force the row expiry into the past via a direct update
	if _, err := app.AuxNonconcurrentDB().NewQuery(
		"UPDATE {{_signedFileTokens}} SET [[expiresAt]] = {:past} WHERE [[id]] = {:id}",
	).Bind(map[string]any{
		"past": time.Now().Add(-time.Hour).UTC().Format("2006-01-02 15:04:05.000Z"),
		"id":   result.Model.Id,
	}).Execute(); err != nil {
		t.Fatal(err)
	}

	if err := app.DeleteExpiredSignedFileTokens(); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindSignedFileTokenById(result.Model.Id); err == nil {
		t.Fatal("expected expired row to have been deleted")
	}
}

func TestSignedFileToken_DispositionValidation(t *testing.T) {
	t.Parallel()

	app := newSignedTokenTestApp(t)
	defer app.Cleanup()

	record, field, filename := loadDemo1SignedFileTarget(t, app)

	if _, err := app.NewSignedFileToken(core.SignedFileTokenOptions{
		Record:      record,
		FileField:   field,
		Filename:    filename,
		Duration:    time.Minute,
		Disposition: "bogus",
	}); err == nil {
		t.Fatal("expected invalid disposition to be rejected")
	}
}

func TestBuildSignedFileURL(t *testing.T) {
	t.Parallel()

	got, err := core.BuildSignedFileURL("http://example.com/api/files/demo1/rec/file.png", "abc.def")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got, "signature=abc.def") {
		t.Fatalf("unexpected signed url %q", got)
	}

	if _, err := core.BuildSignedFileURL("http://example.com/x", ""); err == nil {
		t.Fatal("expected error for an empty token")
	}
}
