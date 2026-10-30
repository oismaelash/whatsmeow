// Package pilotupgrades contains the database schema of the tables that only exist in the
// Pilot Status fork of whatsmeow.
//
// PILOT-STATUS FORK (group SKD tracking): these tables are versioned in their own version
// table (whatsmeow_pilot_version) instead of the upstream whatsmeow_version, so that merging
// new upstream migrations (which are numbered sequentially) never collides with ours.
package pilotupgrades

import (
	"embed"

	"go.mau.fi/util/dbutil"
)

//go:embed *.sql
var upgrades embed.FS

// VersionTable is the name of the table that stores the version of the fork-only schema.
const VersionTable = "whatsmeow_pilot_version"

var Table = dbutil.BuildUpgradeTable().WithFS(upgrades).Finish()
