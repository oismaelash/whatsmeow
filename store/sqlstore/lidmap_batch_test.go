// PILOT-STATUS FORK (lidmap-batch): unit tests for the batched LID map write
// plan. They need no database: the upstream per-mapping loop and the batched
// plan are both simulated on an in-memory table and must end in the same state.

package sqlstore

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// lidTable models whatsmeow_lid_map: lid is the primary key, pn is UNIQUE.
type lidTable map[string]string // lid -> pn

func (t lidTable) pnOwner(pn string) (string, bool) {
	for lid, p := range t {
		if p == pn {
			return lid, true
		}
	}
	return "", false
}

// applyUpstream replays the upstream unlockedPutLIDMapping loop.
func applyUpstream(t lidTable, mappings []store.LIDMapping) {
	for _, m := range mappings {
		lid, pn := m.LID.User, m.PN.User
		// DELETE FROM whatsmeow_lid_map WHERE (lid<>$1 AND pn=$2)
		for l, p := range t {
			if l != lid && p == pn {
				delete(t, l)
			}
		}
		// INSERT ... ON CONFLICT (lid) DO UPDATE SET pn=excluded.pn
		t[lid] = pn
	}
}

// applyPlan replays execLIDMappingPlan, failing on any UNIQUE(pn) violation
// the real database would raise.
func applyPlan(tb testing.TB, t lidTable, plan lidMappingPlan) {
	tb.Helper()
	for _, lid := range plan.DroppedLIDs {
		delete(t, lid)
	}
	finalLIDForPN := make(map[string]string, len(plan.Final))
	for _, pair := range plan.Final {
		finalLIDForPN[pair.PN] = pair.LID
	}
	for _, pn := range plan.TouchedPNs {
		finalLID, hasFinal := finalLIDForPN[pn]
		for l, p := range t {
			if p == pn && (!hasFinal || l != finalLID) {
				delete(t, l)
			}
		}
	}
	for _, pair := range plan.Final {
		if owner, ok := t.pnOwner(pair.PN); ok && owner != pair.LID {
			tb.Fatalf("upsert of %s->%s would violate UNIQUE(pn): held by %s", pair.LID, pair.PN, owner)
		}
		t[pair.LID] = pair.PN
	}
}

func mapping(lid, pn string) store.LIDMapping {
	return store.LIDMapping{
		LID: types.JID{User: lid, Server: types.HiddenUserServer},
		PN:  types.JID{User: pn, Server: types.DefaultUserServer},
	}
}

func TestPlanLIDMappingWriteMatchesUpstreamLoop(t *testing.T) {
	cases := []struct {
		name     string
		initial  lidTable
		mappings []store.LIDMapping
	}{
		{"new rows", lidTable{}, []store.LIDMapping{mapping("l2", "p2"), mapping("l1", "p1")}},
		{"unchanged row", lidTable{"l1": "p1"}, []store.LIDMapping{mapping("l1", "p1")}},
		{"lid gets new pn", lidTable{"l1": "p1"}, []store.LIDMapping{mapping("l1", "p9")}},
		{"pn moves to new lid", lidTable{"l1": "p1"}, []store.LIDMapping{mapping("l2", "p1")}},
		{"swap two rows", lidTable{"a": "p1", "b": "p2"}, []store.LIDMapping{mapping("a", "p2"), mapping("b", "p1")}},
		{"later entry drops earlier lid", lidTable{"x": "p5"}, []store.LIDMapping{mapping("a", "p1"), mapping("b", "p1")}},
		{"lid moves twice", lidTable{}, []store.LIDMapping{mapping("a", "p1"), mapping("a", "p2")}},
		{"dropped lid had an old row", lidTable{"a": "p0"}, []store.LIDMapping{mapping("a", "p1"), mapping("b", "p1")}},
		{"chain", lidTable{"a": "p1", "b": "p2", "c": "p3"}, []store.LIDMapping{mapping("a", "p2"), mapping("b", "p3"), mapping("c", "p1")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := maps.Clone(tc.initial)
			applyUpstream(want, tc.mappings)
			got := maps.Clone(tc.initial)
			applyPlan(t, got, planLIDMappingWrite(tc.mappings))
			if !maps.Equal(want, got) {
				t.Fatalf("table mismatch\nupstream: %v\nbatched:  %v", want, got)
			}
		})
	}
}

func TestPlanLIDMappingWriteRandomized(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for iter := 0; iter < 5000; iter++ {
		initial := lidTable{}
		for i := 0; i < rng.IntN(8); i++ {
			lid, pn := fmt.Sprintf("l%d", rng.IntN(8)), fmt.Sprintf("p%d", rng.IntN(8))
			if _, taken := initial.pnOwner(pn); !taken {
				initial[lid] = pn
			}
		}
		batch := make([]store.LIDMapping, rng.IntN(10))
		for i := range batch {
			batch[i] = mapping(fmt.Sprintf("l%d", rng.IntN(8)), fmt.Sprintf("p%d", rng.IntN(8)))
		}
		want := maps.Clone(initial)
		applyUpstream(want, batch)
		got := maps.Clone(initial)
		applyPlan(t, got, planLIDMappingWrite(batch))
		if !maps.Equal(want, got) {
			t.Fatalf("iteration %d: table mismatch\ninitial:  %v\nbatch:    %v\nupstream: %v\nbatched:  %v", iter, initial, batch, want, got)
		}
	}
}

func TestPlanLIDMappingWriteIsSorted(t *testing.T) {
	batch := []store.LIDMapping{
		mapping("l9", "p1"), mapping("l3", "p7"), mapping("l5", "p2"),
		mapping("l1", "p9"), mapping("l7", "p7"), mapping("l2", "p0"),
	}
	plan := planLIDMappingWrite(batch)
	if !slices.IsSortedFunc(plan.Final, func(a, b lidPair) int { return strings.Compare(a.LID, b.LID) }) {
		t.Fatalf("final pairs not sorted by lid: %v", plan.Final)
	}
	if !slices.IsSorted(plan.TouchedPNs) {
		t.Fatalf("touched pns not sorted: %v", plan.TouchedPNs)
	}
	if !slices.IsSorted(plan.DroppedLIDs) {
		t.Fatalf("dropped lids not sorted: %v", plan.DroppedLIDs)
	}
	// l3->p7 is superseded by l7->p7.
	if !slices.Equal(plan.DroppedLIDs, []string{"l3"}) {
		t.Fatalf("unexpected dropped lids: %v", plan.DroppedLIDs)
	}
	// The plan must not depend on the input order of independent mappings.
	shuffled := []store.LIDMapping{batch[5], batch[0], batch[3], batch[2], batch[1], batch[4]}
	if again := planLIDMappingWrite(shuffled); !slices.Equal(plan.Final, again.Final) {
		t.Fatalf("plan depends on input order: %v vs %v", plan.Final, again.Final)
	}
}

func TestLIDMappingQueriesAreMultiRow(t *testing.T) {
	plan := planLIDMappingWrite([]store.LIDMapping{mapping("b", "p2"), mapping("a", "p1"), mapping("c", "p1")})
	query, args := putLIDMappingsMassInsertBuilder.Build([0]any{}, plan.Final)
	if strings.Count(query, "(") < 3 || !strings.Contains(query, "($1, $2), ($3, $4)") {
		t.Fatalf("expected one multi-row insert, got %q", query)
	}
	if !strings.Contains(query, "ON CONFLICT (lid) DO UPDATE") {
		t.Fatalf("expected upsert, got %q", query)
	}
	if want := []any{"b", "p2", "c", "p1"}; !slices.Equal(args, want) {
		t.Fatalf("insert args = %v, want %v (sorted by lid)", args, want)
	}

	finalLIDForPN := map[string]string{"p1": "c", "p2": "b"}
	delQuery, delArgs := buildDeleteStalePNsQuery([]string{"p1", "p2", "p3"}, finalLIDForPN)
	wantDel := `DELETE FROM whatsmeow_lid_map WHERE (pn=$1 AND lid<>$2) OR (pn=$3 AND lid<>$4) OR pn IN ($5)`
	if delQuery != wantDel {
		t.Fatalf("delete query = %q, want %q", delQuery, wantDel)
	}
	if want := []any{"p1", "c", "p2", "b", "p3"}; !slices.Equal(delArgs, want) {
		t.Fatalf("delete args = %v, want %v", delArgs, want)
	}

	dropQuery, dropArgs := buildDeleteDroppedLIDsQuery([]string{"a", "d"})
	if dropQuery != `DELETE FROM whatsmeow_lid_map WHERE lid IN ($1,$2)` || !slices.Equal(dropArgs, []any{"a", "d"}) {
		t.Fatalf("unexpected dropped lid delete: %q %v", dropQuery, dropArgs)
	}
}

func TestApplyCachedLIDMappingMatchesUpstream(t *testing.T) {
	m := &CachedLIDMap{pnToLIDCache: map[string]string{}, lidToPNCache: map[string]string{}}
	m.applyCachedLIDMapping("l1", "p1")
	m.applyCachedLIDMapping("l1", "p2") // lid moves: p1 must be forgotten
	m.applyCachedLIDMapping("l2", "p2") // pn moves: l1 must be forgotten
	if !maps.Equal(m.pnToLIDCache, map[string]string{"p2": "l2"}) {
		t.Fatalf("pnToLID = %v", m.pnToLIDCache)
	}
	if !maps.Equal(m.lidToPNCache, map[string]string{"l2": "p2"}) {
		t.Fatalf("lidToPN = %v", m.lidToPNCache)
	}
}
