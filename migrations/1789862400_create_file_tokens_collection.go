package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		if txApp.HasTable(core.CollectionNameFileTokens) {
			return nil // already applied
		}

		col := core.NewBaseCollection(core.CollectionNameFileTokens)
		col.System = true

		// only the superusers and the minting auth records can manage
		// (list/revoke) their signed URLs; downloads never go through
		// the regular record API so there is no ViewRule-based access
		ownerRule := "@request.auth.id != '' && createdBy = @request.auth.id && createdByCollection = @request.auth.collectionId"
		col.ListRule = types.Pointer(ownerRule)
		col.ViewRule = types.Pointer(ownerRule)
		col.DeleteRule = types.Pointer(ownerRule)

		// target file binding
		col.Fields.Add(&core.TextField{
			Name:     "collectionRef",
			System:   true,
			Required: true,
		})
		col.Fields.Add(&core.TextField{
			Name:     "recordRef",
			System:   true,
			Required: true,
		})
		col.Fields.Add(&core.TextField{
			Name:     "fileField",
			System:   true,
			Required: true,
		})
		col.Fields.Add(&core.TextField{
			Name:     "filename",
			System:   true,
			Required: true,
		})

		// signed response disposition ("auto", "inline" or "attachment")
		col.Fields.Add(&core.TextField{
			Name:     "disposition",
			System:   true,
			Required: true,
		})

		// who minted the URL (auth record polymorphic ref)
		col.Fields.Add(&core.TextField{
			Name:     "createdByCollection",
			System:   true,
			Required: true,
		})
		col.Fields.Add(&core.TextField{
			Name:     "createdBy",
			System:   true,
			Required: true,
		})

		col.Fields.Add(&core.DateField{
			Name:     "expiresAt",
			System:   true,
			Required: true,
		})

		col.Fields.Add(&core.AutodateField{
			Name:     "created",
			System:   true,
			OnCreate: true,
		})
		col.Fields.Add(&core.AutodateField{
			Name:     "updated",
			System:   true,
			OnCreate: true,
			OnUpdate: true,
		})

		col.AddIndex("idx_fileTokens_target", false, "collectionRef,recordRef", "")
		col.AddIndex("idx_fileTokens_creator", false, "createdByCollection,createdBy", "")
		col.AddIndex("idx_fileTokens_expiresAt", false, "expiresAt", "")

		return txApp.Save(col)
	}, func(txApp core.App) error {
		return txApp.DeleteTable(core.CollectionNameFileTokens)
	})
}
