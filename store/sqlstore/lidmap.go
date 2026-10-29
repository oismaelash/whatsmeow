// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package sqlstore contains an SQL-backed implementation of the interfaces in the store package.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exslices"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

type CachedLIDMap struct {
	db *dbutil.Database

	pnToLIDCache map[string]string
	lidToPNCache map[string]string
	cacheFilled  bool
	lidCacheLock sync.RWMutex

	// PILOT-STATUS FORK (lidmap-batch): writes are serialised by lidWriteLock
	// instead of lidCacheLock, so lidCacheLock is only ever held for in-memory
	// cache access and never across database I/O. cacheGen is bumped (under
	// lidCacheLock) every time a writer applies committed mappings to the cache;
	// readers that query the database without the lock only populate the cache
	// when cacheGen has not moved, so a stale read can never overwrite a newer
	// committed write.
	lidWriteLock sync.Mutex
	cacheGen     uint64
}

var _ store.LIDStore = (*CachedLIDMap)(nil)

func NewCachedLIDMap(db *dbutil.Database) *CachedLIDMap {
	return &CachedLIDMap{
		db: db,

		pnToLIDCache: make(map[string]string),
		lidToPNCache: make(map[string]string),
	}
}

const (
	putLIDMappingQuery = `
		INSERT INTO whatsmeow_lid_map (lid, pn)
		VALUES ($1, $2)
		ON CONFLICT (lid) DO UPDATE SET pn=excluded.pn WHERE whatsmeow_lid_map.pn<>excluded.pn
	`
	getLIDForPNQuery       = `SELECT lid FROM whatsmeow_lid_map WHERE pn=$1`
	getPNForLIDQuery       = `SELECT pn FROM whatsmeow_lid_map WHERE lid=$1`
	getAllLIDMappingsQuery = `SELECT lid, pn FROM whatsmeow_lid_map`
)

var convertLIDRow = dbutil.ConvertRowFn[store.LIDMapping](func(rows dbutil.Scannable) (store.LIDMapping, error) {
	var lidUser, pnUser string
	err := rows.Scan(&lidUser, &pnUser)
	if err != nil {
		return store.LIDMapping{}, err
	}
	return store.LIDMapping{
		LID: types.JID{User: lidUser, Server: types.DefaultUserServer},
		PN:  types.JID{User: pnUser, Server: types.DefaultUserServer},
	}, nil
})

func (s *CachedLIDMap) FillCache(ctx context.Context) error {
	s.lidCacheLock.Lock()
	defer s.lidCacheLock.Unlock()
	res := convertLIDRow.NewRowIter(s.db.Query(ctx, getAllLIDMappingsQuery))
	err := s.scanManyLids(res, nil)
	s.cacheFilled = err == nil
	// PILOT-STATUS FORK (lidmap-batch): invalidate lock-free reads in flight.
	s.cacheGen++
	return err
}

func (s *CachedLIDMap) scanManyLids(res dbutil.RowIter[store.LIDMapping], fn func(lid, pn string)) error {
	return res.Iter(func(mapping store.LIDMapping) (bool, error) {
		s.pnToLIDCache[mapping.PN.User] = mapping.LID.User
		s.lidToPNCache[mapping.LID.User] = mapping.PN.User
		if fn != nil {
			fn(mapping.LID.User, mapping.PN.User)
		}
		return true, nil
	})
}

// PILOT-STATUS FORK (lidmap-batch): upstream held lidCacheLock (exclusively)
// while querying the database on a cache miss, so a single slow query blocked
// every LID lookup of every client sharing the map, including the ones inside
// SendMessage. The query now runs without the lock and the result is only
// written to the cache if no writer applied a mapping in the meantime
// (see cacheGen).
func (s *CachedLIDMap) getLIDMapping(ctx context.Context, source types.JID, targetServer, query string, sourceToTarget, targetToSource map[string]string) (types.JID, error) {
	s.lidCacheLock.RLock()
	targetUser, ok := sourceToTarget[source.User]
	cacheFilled := s.cacheFilled
	gen := s.cacheGen
	s.lidCacheLock.RUnlock()
	if ok || cacheFilled {
		if targetUser == "" {
			return types.JID{}, nil
		}
		return types.JID{User: targetUser, Device: source.Device, Server: targetServer}, nil
	}
	err := s.db.QueryRow(ctx, query, source.User).Scan(&targetUser)
	if errors.Is(err, sql.ErrNoRows) {
		// continue with empty result
	} else if err != nil {
		return types.JID{}, err
	}
	s.lidCacheLock.Lock()
	if s.cacheGen == gen {
		sourceToTarget[source.User] = targetUser
		if targetUser != "" {
			targetToSource[targetUser] = source.User
		}
	}
	s.lidCacheLock.Unlock()
	if targetUser != "" {
		return types.JID{User: targetUser, Device: source.Device, Server: targetServer}, nil
	}
	return types.JID{}, nil
}

func (s *CachedLIDMap) GetLIDForPN(ctx context.Context, pn types.JID) (types.JID, error) {
	if pn.Server != types.DefaultUserServer {
		return types.JID{}, fmt.Errorf("invalid GetLIDForPN call with non-PN JID %s", pn)
	}
	return s.getLIDMapping(
		ctx, pn, types.HiddenUserServer, getLIDForPNQuery,
		s.pnToLIDCache, s.lidToPNCache,
	)
}

func (s *CachedLIDMap) GetPNForLID(ctx context.Context, lid types.JID) (types.JID, error) {
	if lid.Server != types.HiddenUserServer {
		return types.JID{}, fmt.Errorf("invalid GetPNForLID call with non-LID JID %s", lid)
	}
	return s.getLIDMapping(
		ctx, lid, types.DefaultUserServer, getPNForLIDQuery,
		s.lidToPNCache, s.pnToLIDCache,
	)
}

// PILOT-STATUS FORK (lidmap-batch): same as getLIDMapping, the cache-miss query
// runs without lidCacheLock and the cache is populated afterwards, guarded by
// cacheGen. The returned result is identical to upstream.
func (s *CachedLIDMap) GetManyLIDsForPNs(ctx context.Context, pns []types.JID) (map[types.JID]types.JID, error) {
	if len(pns) == 0 {
		return nil, nil
	}

	result := make(map[types.JID]types.JID, len(pns))

	s.lidCacheLock.RLock()
	missingPNs := make([]string, 0, len(pns))
	missingPNDevices := make(map[string][]types.JID)
	for _, pn := range pns {
		if pn.Server != types.DefaultUserServer {
			continue
		}
		if lidUser, ok := s.pnToLIDCache[pn.User]; ok && lidUser != "" {
			result[pn] = types.JID{User: lidUser, Device: pn.Device, Server: types.HiddenUserServer}
		} else if !s.cacheFilled {
			missingPNs = append(missingPNs, pn.User)
			missingPNDevices[pn.User] = append(missingPNDevices[pn.User], pn)
		}
	}
	gen := s.cacheGen
	s.lidCacheLock.RUnlock()

	if len(missingPNs) == 0 {
		return result, nil
	}

	var res dbutil.RowIter[store.LIDMapping]
	if s.db.Dialect == dbutil.Postgres && PostgresArrayWrapper != nil {
		res = convertLIDRow.NewRowIter(s.db.Query(
			ctx,
			`SELECT lid, pn FROM whatsmeow_lid_map WHERE pn = ANY($1)`,
			PostgresArrayWrapper(missingPNs),
		))
	} else {
		placeholders := make([]string, len(missingPNs))
		for i := range missingPNs {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}
		res = convertLIDRow.NewRowIter(s.db.Query(
			ctx,
			fmt.Sprintf(`SELECT lid, pn FROM whatsmeow_lid_map WHERE pn IN (%s)`, strings.Join(placeholders, ",")),
			exslices.CastToAny(missingPNs)...,
		))
	}
	found, err := res.AsList()
	for _, mapping := range found {
		for _, dev := range missingPNDevices[mapping.PN.User] {
			lidDev := dev
			lidDev.Server = types.HiddenUserServer
			lidDev.User = mapping.LID.User
			result[dev] = lidDev.ToNonAD()
		}
	}
	if len(found) > 0 {
		s.lidCacheLock.Lock()
		if s.cacheGen == gen {
			for _, mapping := range found {
				s.pnToLIDCache[mapping.PN.User] = mapping.LID.User
				s.lidToPNCache[mapping.LID.User] = mapping.PN.User
			}
		}
		s.lidCacheLock.Unlock()
	}
	return result, err
}

// PILOT-STATUS FORK (lidmap-batch): routed through PutManyLIDMappings so that
// single and batched writes share the same batched code path that does not hold
// lidCacheLock during database I/O. The error for an invalid pair is kept
// (PutManyLIDMappings silently drops invalid pairs).
func (s *CachedLIDMap) PutLIDMapping(ctx context.Context, lid, pn types.JID) error {
	if lid.Server != types.HiddenUserServer || pn.Server != types.DefaultUserServer {
		return fmt.Errorf("invalid PutLIDMapping call %s/%s", lid, pn)
	}
	return s.PutManyLIDMappings(ctx, []store.LIDMapping{{LID: lid, PN: pn}})
}

// PILOT-STATUS FORK (lidmap-batch): rewritten for production group sends.
//
// Upstream ran one DELETE + one INSERT per mapping, in input order, inside a
// transaction, while holding lidCacheLock for the whole transaction. With many
// clients in the same groups this produced lock waits of minutes and deadlocks
// on whatsmeow_lid_map, and every LID lookup (including the ones inside
// SendMessage) queued behind the lock.
//
// This version produces exactly the same table and cache contents as the
// upstream loop, but:
//   - computes the end state of the loop in memory (planLIDMappingWrite),
//   - writes it with a bounded number of multi-row statements, with keys in
//     sorted order so concurrent writers take row locks in the same order,
//   - only deletes rows that the upstream loop would also have removed,
//   - does not hold lidCacheLock during database I/O: the cache is updated
//     after the transaction commits, replaying the upstream cache logic.
//
// Writers in the same process are serialised by lidWriteLock (upstream got the
// same serialisation from lidCacheLock), so they cannot deadlock each other.
func (s *CachedLIDMap) PutManyLIDMappings(ctx context.Context, mappings []store.LIDMapping) error {
	s.lidWriteLock.Lock()
	defer s.lidWriteLock.Unlock()

	s.lidCacheLock.RLock()
	mappings = slices.DeleteFunc(mappings, func(mapping store.LIDMapping) bool {
		if mapping.LID.Server != types.HiddenUserServer || mapping.PN.Server != types.DefaultUserServer {
			zerolog.Ctx(ctx).Debug().
				Stringer("entry_lid", mapping.LID).
				Stringer("entry_pn", mapping.PN).
				Msg("Ignoring invalid entry in PutManyLIDMappings")
			return true
		}
		cachedLID, ok := s.pnToLIDCache[mapping.PN.User]
		if ok && cachedLID == mapping.LID.User {
			return true
		}
		return false
	})
	s.lidCacheLock.RUnlock()
	mappings = exslices.DeduplicateUnsortedOverwrite(mappings)
	if len(mappings) == 0 {
		return nil
	}

	plan := planLIDMappingWrite(mappings)
	err := s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		return s.execLIDMappingPlan(ctx, plan)
	})
	if err != nil {
		return err
	}

	s.lidCacheLock.Lock()
	for _, mapping := range mappings {
		s.applyCachedLIDMapping(mapping.LID.User, mapping.PN.User)
	}
	s.cacheGen++
	s.lidCacheLock.Unlock()
	return nil
}

// applyCachedLIDMapping is the cache half of upstream's unlockedPutLIDMapping,
// unchanged. It must be called with lidCacheLock held for writing.
func (s *CachedLIDMap) applyCachedLIDMapping(lid, pn string) {
	oldLID := s.pnToLIDCache[pn]
	oldPN := s.lidToPNCache[lid]
	s.pnToLIDCache[pn] = lid
	s.lidToPNCache[lid] = pn
	if oldPN != "" && oldPN != pn && s.pnToLIDCache[oldPN] == lid {
		delete(s.pnToLIDCache, oldPN)
	}
	if oldLID != "" && oldLID != lid && s.lidToPNCache[oldLID] == pn {
		delete(s.lidToPNCache, oldLID)
	}
}

// PILOT-STATUS FORK (lidmap-batch): lidMappingPlan is the end state that the
// upstream per-mapping loop
//
//	DELETE FROM whatsmeow_lid_map WHERE lid<>$lid AND pn=$pn
//	INSERT ... (lid, pn) ON CONFLICT (lid) DO UPDATE SET pn=excluded.pn
//
// produces for one batch, expressed as set operations:
//   - Final: the rows that exist afterwards among the touched keys, sorted by
//     lid (lid and pn are both unique, so this is a 1:1 set).
//   - DroppedLIDs: lids written by the batch whose row a later entry of the same
//     batch deleted again (its pn went to another lid). Sorted.
//   - TouchedPNs: every pn written by the batch, sorted. Afterwards no row may
//     hold one of these pns unless it is the Final row for that pn.
//
// Deleting the rows with lid in DroppedLIDs, then the rows with pn in
// TouchedPNs that are not Final, then upserting Final gives the same table as
// the upstream loop. After the deletes the upsert can only conflict with an
// identical row, so it can never violate UNIQUE(pn).
type lidMappingPlan struct {
	Final       []lidPair
	DroppedLIDs []string
	TouchedPNs  []string
}

type lidPair struct {
	LID string
	PN  string
}

func (lp lidPair) GetMassInsertValues() [2]any {
	return [...]any{lp.LID, lp.PN}
}

func planLIDMappingWrite(mappings []store.LIDMapping) lidMappingPlan {
	lidToPN := make(map[string]string, len(mappings))
	pnToLID := make(map[string]string, len(mappings))
	touchedLIDs := make(map[string]struct{}, len(mappings))
	touchedPNs := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		lid, pn := mapping.LID.User, mapping.PN.User
		touchedLIDs[lid] = struct{}{}
		touchedPNs[pn] = struct{}{}
		// DELETE ... WHERE lid<>$lid AND pn=$pn
		if otherLID, ok := pnToLID[pn]; ok && otherLID != lid {
			delete(lidToPN, otherLID)
		}
		// ON CONFLICT (lid) DO UPDATE SET pn=$pn: the lid releases its old pn
		if oldPN, ok := lidToPN[lid]; ok && oldPN != pn {
			delete(pnToLID, oldPN)
		}
		lidToPN[lid] = pn
		pnToLID[pn] = lid
	}
	plan := lidMappingPlan{
		Final:      make([]lidPair, 0, len(lidToPN)),
		TouchedPNs: make([]string, 0, len(touchedPNs)),
	}
	for lid, pn := range lidToPN {
		plan.Final = append(plan.Final, lidPair{LID: lid, PN: pn})
	}
	for lid := range touchedLIDs {
		if _, ok := lidToPN[lid]; !ok {
			plan.DroppedLIDs = append(plan.DroppedLIDs, lid)
		}
	}
	for pn := range touchedPNs {
		plan.TouchedPNs = append(plan.TouchedPNs, pn)
	}
	slices.SortFunc(plan.Final, func(a, b lidPair) int { return strings.Compare(a.LID, b.LID) })
	slices.Sort(plan.DroppedLIDs)
	slices.Sort(plan.TouchedPNs)
	return plan
}

// PILOT-STATUS FORK (lidmap-batch): rows per statement. The largest statement
// (the stale pn delete) binds 2 parameters per row, far below the SQLite
// (32766) and Postgres (65535) parameter limits.
const lidMapBatchSize = 500

var putLIDMappingsMassInsertBuilder = dbutil.NewMassInsertBuilder[lidPair, [0]any](
	putLIDMappingQuery, "($%d, $%d)",
)

func (s *CachedLIDMap) execLIDMappingPlan(ctx context.Context, plan lidMappingPlan) error {
	for chunk := range slices.Chunk(plan.DroppedLIDs, lidMapBatchSize) {
		query, args := buildDeleteDroppedLIDsQuery(chunk)
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to delete dropped LID mappings: %w", err)
		}
	}
	finalLIDForPN := make(map[string]string, len(plan.Final))
	for _, pair := range plan.Final {
		finalLIDForPN[pair.PN] = pair.LID
	}
	for chunk := range slices.Chunk(plan.TouchedPNs, lidMapBatchSize) {
		query, args := buildDeleteStalePNsQuery(chunk, finalLIDForPN)
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to delete stale LID mappings: %w", err)
		}
	}
	for chunk := range slices.Chunk(plan.Final, lidMapBatchSize) {
		query, args := putLIDMappingsMassInsertBuilder.Build([0]any{}, chunk)
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to upsert LID mappings: %w", err)
		}
	}
	return nil
}

func buildDeleteDroppedLIDsQuery(lids []string) (string, []any) {
	placeholders := make([]string, len(lids))
	args := make([]any, len(lids))
	for i, lid := range lids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = lid
	}
	return fmt.Sprintf(`DELETE FROM whatsmeow_lid_map WHERE lid IN (%s)`, strings.Join(placeholders, ",")), args
}

// buildDeleteStalePNsQuery deletes every row holding one of the given pns,
// except the row that is final for that pn. A pn with a final lid becomes
// "(pn=$a AND lid<>$b)"; a pn that no row may keep goes into "pn IN (...)".
func buildDeleteStalePNsQuery(pns []string, finalLIDForPN map[string]string) (string, []any) {
	var orphans []string
	conds := make([]string, 0, len(pns)+1)
	args := make([]any, 0, len(pns)*2)
	for _, pn := range pns {
		lid, ok := finalLIDForPN[pn]
		if !ok {
			orphans = append(orphans, pn)
			continue
		}
		args = append(args, pn, lid)
		conds = append(conds, fmt.Sprintf("(pn=$%d AND lid<>$%d)", len(args)-1, len(args)))
	}
	if len(orphans) > 0 {
		placeholders := make([]string, len(orphans))
		for i, pn := range orphans {
			args = append(args, pn)
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		conds = append(conds, fmt.Sprintf("pn IN (%s)", strings.Join(placeholders, ",")))
	}
	return `DELETE FROM whatsmeow_lid_map WHERE ` + strings.Join(conds, " OR "), args
}
