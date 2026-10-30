// Copyright (c) 2026 Pilot Status
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

// PILOT-STATUS FORK (group SKD tracking): persistence for store.SenderKeyDistributionStore.
//
// Upstream whatsmeow encrypts the SenderKeyDistributionMessage for every device of a group on
// every group message. This table remembers which devices already received our current sender
// key, so that only new or invalidated devices need it. The table is in the fork-only schema
// (see pilotupgrades), and every session or identity reset of a device in this file's hooks
// removes its entries, so a device whose Signal state changed always gets the key again.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mau.fi/util/dbutil"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

const (
	getSKDRecipientsQuery = `
		SELECT device_jid, key_id, iteration, sent_at FROM whatsmeow_pilot_skd_recipients
		WHERE our_jid=$1 AND chat_id=$2
	`
	putSKDRecipientQuery = `
		INSERT INTO whatsmeow_pilot_skd_recipients (our_jid, chat_id, key_id, iteration, sent_at, device_jid, their_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (our_jid, chat_id, device_jid) DO UPDATE
			SET key_id=excluded.key_id, iteration=excluded.iteration, sent_at=excluded.sent_at, their_id=excluded.their_id
	`
	deleteAllSKDRecipientsQuery              = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND chat_id=$2`
	deleteSKDRecipientsByDeviceQueryPostgres = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND chat_id=$2 AND device_jid = ANY($3)`
	deleteSKDRecipientsByDeviceQueryGeneric  = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND chat_id=$2 AND device_jid IN (%s)`
	deleteSKDRecipientsByAddrInChatPostgres  = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND chat_id=$2 AND their_id = ANY($3)`
	deleteSKDRecipientsByAddrInChatGeneric   = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND chat_id=$2 AND their_id IN (%s)`
	deleteSKDRecipientsByAddrQueryPostgres   = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND their_id = ANY($2)`
	deleteSKDRecipientsByAddrQueryGeneric    = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND their_id IN (%s)`
	deleteSKDRecipientsByAddrSingleQuery     = `DELETE FROM whatsmeow_pilot_skd_recipients WHERE our_jid=$1 AND their_id=$2`
	// Matches both "user:device" and "user_agent:device" (LID) addresses of a user.
	deleteSKDRecipientsByUserQuery = `
		DELETE FROM whatsmeow_pilot_skd_recipients
		WHERE our_jid=$1 AND (their_id LIKE $2 ESCAPE '\' OR their_id LIKE $3 ESCAPE '\')
	`
	// Only invalidate when the identity really changed: PutIdentity is called for every
	// prekey message, and the identity is usually the same one.
	deleteSKDRecipientsOnIdentityChangeQuery = `
		DELETE FROM whatsmeow_pilot_skd_recipients
		WHERE our_jid=$1 AND their_id=$2 AND EXISTS (
			SELECT 1 FROM whatsmeow_identity_keys
			WHERE whatsmeow_identity_keys.our_jid=$1 AND whatsmeow_identity_keys.their_id=$2
			  AND whatsmeow_identity_keys.identity<>$3
		)
	`
)

// 2 dynamic parameters per row plus 5 static ones, well under SQLite's variable limit.
const skdRecipientBatchSize = 400

var _ store.SenderKeyDistributionStore = (*SQLStore)(nil)

type skdRecipientEntry store.SKDRecipient

func (e skdRecipientEntry) GetMassInsertValues() [2]any {
	return [...]any{e.Device.String(), e.Address}
}

var putSKDRecipientsMassInsertBuilder = dbutil.NewMassInsertBuilder[skdRecipientEntry, [5]any](
	putSKDRecipientQuery, "($1, $2, $3, $4, $5, $%d, $%d)",
)

func (s *SQLStore) GetSKDRecipients(ctx context.Context, group types.JID) (map[types.JID]store.SKDState, error) {
	rows, err := s.db.Query(ctx, getSKDRecipientsQuery, s.JID, group.String())
	if err != nil {
		return nil, err
	}
	result := make(map[types.JID]store.SKDState)
	err = dbutil.NewRowIterWithError(rows, func(row dbutil.Scannable) (struct{}, error) {
		var deviceStr string
		var keyID, iteration, sentAt int64
		if err := row.Scan(&deviceStr, &keyID, &iteration, &sentAt); err != nil {
			return struct{}{}, err
		}
		device, err := types.ParseJID(deviceStr)
		if err != nil {
			// Unparseable entries are simply not trusted: the device will get the key again.
			return struct{}{}, nil
		}
		result[device] = store.SKDState{
			KeyID:     uint32(keyID),
			Iteration: uint32(iteration),
			SentAt:    time.UnixMilli(sentAt),
		}
		return struct{}{}, nil
	}, nil).Iter(func(struct{}) (bool, error) { return true, nil })
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SQLStore) PutSKDRecipients(ctx context.Context, group types.JID, keyID, iteration uint32, recipients []store.SKDRecipient) error {
	if len(recipients) == 0 {
		return nil
	}
	entries := make([]skdRecipientEntry, len(recipients))
	for i, r := range recipients {
		entries[i] = skdRecipientEntry(r)
	}
	// Sorted so that concurrent writers lock rows in the same order.
	slices.SortFunc(entries, func(a, b skdRecipientEntry) int {
		return strings.Compare(a.Device.String(), b.Device.String())
	})
	entries = slices.CompactFunc(entries, func(a, b skdRecipientEntry) bool { return a.Device == b.Device })
	static := [5]any{s.JID, group.String(), int64(keyID), int64(iteration), time.Now().UnixMilli()}
	return s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		for chunk := range slices.Chunk(entries, skdRecipientBatchSize) {
			query, args := putSKDRecipientsMassInsertBuilder.Build(static, chunk)
			if _, err := s.db.Exec(ctx, query, args...); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) DeleteSKDRecipients(ctx context.Context, group types.JID, devices []types.JID) error {
	if len(devices) == 0 {
		return nil
	}
	strs := make([]string, len(devices))
	for i, dev := range devices {
		strs[i] = dev.String()
	}
	return s.execWithStringList(ctx, deleteSKDRecipientsByDeviceQueryPostgres, deleteSKDRecipientsByDeviceQueryGeneric,
		[]any{s.JID, group.String()}, strs)
}

func (s *SQLStore) DeleteSKDRecipientsByAddress(ctx context.Context, group types.JID, addresses []string) error {
	if len(addresses) == 0 {
		return nil
	}
	if group.IsEmpty() {
		return s.execWithStringList(ctx, deleteSKDRecipientsByAddrQueryPostgres, deleteSKDRecipientsByAddrQueryGeneric,
			[]any{s.JID}, addresses)
	}
	return s.execWithStringList(ctx, deleteSKDRecipientsByAddrInChatPostgres, deleteSKDRecipientsByAddrInChatGeneric,
		[]any{s.JID, group.String()}, addresses)
}

func (s *SQLStore) DeleteSKDRecipientsForUser(ctx context.Context, user string) error {
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(user)
	_, err := s.db.Exec(ctx, deleteSKDRecipientsByUserQuery, s.JID, escaped+":%", escaped+`\_%:%`)
	return err
}

func (s *SQLStore) DeleteAllSKDRecipients(ctx context.Context, group types.JID) error {
	_, err := s.db.Exec(ctx, deleteAllSKDRecipientsQuery, s.JID, group.String())
	return err
}

// execWithStringList runs a query whose last parameter is a list of strings, using a native
// array on Postgres and an expanded IN (...) list elsewhere.
func (s *SQLStore) execWithStringList(ctx context.Context, pgQuery, genericQuery string, fixed []any, list []string) error {
	if s.db.Dialect == dbutil.Postgres && PostgresArrayWrapper != nil {
		args := append(slices.Clone(fixed), PostgresArrayWrapper(list))
		_, err := s.db.Exec(ctx, pgQuery, args...)
		return err
	}
	for chunk := range slices.Chunk(list, skdRecipientBatchSize) {
		args := slices.Clone(fixed)
		placeholders := make([]string, len(chunk))
		for i, item := range chunk {
			args = append(args, item)
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		if _, err := s.db.Exec(ctx, fmt.Sprintf(genericQuery, strings.Join(placeholders, ",")), args...); err != nil {
			return err
		}
	}
	return nil
}

// The hooks below are called from the session and identity methods. A failure is logged and
// not returned: the Signal operation itself must not fail because of the fork-only table,
// and a stale entry is recovered by the device's retry receipt.

func (s *SQLStore) invalidateSKDByAddress(ctx context.Context, address string) {
	if _, err := s.db.Exec(ctx, deleteSKDRecipientsByAddrSingleQuery, s.JID, address); err != nil {
		s.log.Warnf("Failed to invalidate sender key distribution state of %s: %v", address, err)
	}
}

func (s *SQLStore) invalidateSKDByPhone(ctx context.Context, phone string) {
	if err := s.DeleteSKDRecipientsForUser(ctx, phone); err != nil {
		s.log.Warnf("Failed to invalidate sender key distribution state of %s: %v", phone, err)
	}
}

func (s *SQLStore) invalidateSKDOnIdentityChange(ctx context.Context, address string, key [32]byte) {
	if _, err := s.db.Exec(ctx, deleteSKDRecipientsOnIdentityChangeQuery, s.JID, address, key[:]); err != nil {
		s.log.Warnf("Failed to invalidate sender key distribution state of %s after identity change: %v", address, err)
	}
}
