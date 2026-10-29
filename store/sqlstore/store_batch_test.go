// PILOT-STATUS FORK (sessions-batch): unit test for the batched session upsert.

package sqlstore

import (
	"strings"
	"testing"
)

func TestPutSessionsMassInsertQuery(t *testing.T) {
	query, args := putSessionsMassInsertBuilder.Build([1]any{"me@s.whatsapp.net"}, []sessionEntry{
		{Address: "a.0", Session: []byte{1}},
		{Address: "b.0", Session: []byte{2}},
	})
	if !strings.Contains(query, "($1, $2, $3), ($1, $4, $5)") || !strings.Contains(query, "ON CONFLICT (our_jid, their_id) DO UPDATE SET session=excluded.session") {
		t.Fatalf("unexpected sessions query: %q", query)
	}
	if len(args) != 5 || args[0] != "me@s.whatsapp.net" || args[1] != "a.0" || args[3] != "b.0" {
		t.Fatalf("unexpected sessions args: %v", args)
	}
}
