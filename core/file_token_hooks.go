package core

import (
	"fmt"
	"slices"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/tools/hook"
)

func (app *BaseApp) registerFileTokenHooks() {
	// cascade on target record/collection delete (no collection type
	// restriction: file tokens may point to base, auth and view records)
	recordRefHooks[*FileToken](app, CollectionNameFileTokens)

	// run hourly to cleanup expired signed URL rows
	app.Cron().Add("__pbFileTokensCleanup__", "0 * * * *", func() {
		if err := app.DeleteExpiredFileTokens(); err != nil {
			app.Logger().Warn("Failed to delete expired file tokens", "error", err)
		}
	})

	// revoke signed URLs pointing to files that were removed/replaced during
	// a record update (eg. file rename or deletion), so orphaned rows don't
	// linger until their natural expiration
	app.OnRecordAfterUpdateSuccess().Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := e.Next(); err != nil {
				return err
			}

			if e.Record.Collection().Name == CollectionNameFileTokens {
				return nil
			}

			var removedFiles []string

			for _, f := range e.Record.Collection().Fields {
				fileField, ok := f.(*FileField)
				if !ok {
					continue
				}

				oldNames := fileField.extractPlainStrings(fileField.toSliceValue(e.Record.Original().GetRaw(fileField.Name)))
				newNames := fileField.extractPlainStrings(fileField.toSliceValue(e.Record.GetRaw(fileField.Name)))

				for _, name := range oldNames {
					if !slices.Contains(newNames, name) {
						removedFiles = append(removedFiles, fileField.Name+"\x00"+name)
					}
				}
			}

			if len(removedFiles) == 0 {
				return nil
			}

			rows := []*FileToken{}
			err := e.App.RecordQuery(CollectionNameFileTokens).
				AndWhere(dbx.HashExp{
					"collectionRef": e.Record.Collection().Id,
					"recordRef":     e.Record.Id,
				}).
				All(&rows)
			if err != nil {
				return err
			}

			for _, row := range rows {
				key := row.FileField() + "\x00" + row.Filename()
				if !slices.Contains(removedFiles, key) {
					continue
				}

				if err := e.App.Delete(row); err != nil {
					return fmt.Errorf(
						"[%s] failed to revoke a stale file token for record %q: %w",
						e.Record.Collection().Name,
						e.Record.Id,
						err,
					)
				}
			}

			return nil
		},
		Priority: 99,
	})

	// invalidate every URL minted by an auth record when its tokenKey changes
	// (password change / sign-out everywhere), similar to OTPs/MFAs
	app.OnRecordUpdateExecute().Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			err := e.Next()
			if err != nil || !e.Record.Collection().IsAuth() {
				return err
			}

			if !e.Record.Original().IsNew() && e.Record.Original().TokenKey() != e.Record.TokenKey() {
				models := []*FileToken{}

				err = e.App.RecordQuery(CollectionNameFileTokens).
					AndWhere(dbx.HashExp{
						"createdByCollection": e.Record.Collection().Id,
						"createdBy":           e.Record.Id,
					}).
					All(&models)
				if err != nil {
					return fmt.Errorf(
						"[%s] failed to fetch the file tokens for record %q: %w",
						e.Record.Collection().Name,
						e.Record.Id,
						err,
					)
				}

				for _, m := range models {
					if err := e.App.Delete(m); err != nil {
						return fmt.Errorf(
							"[%s] failed to revoke a file token for record %q: %w",
							e.Record.Collection().Name,
							e.Record.Id,
							err,
						)
					}
				}
			}

			return nil
		},
		Priority: 99,
	})
}
