// Copyright (c) 2026 Pilot Status
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

// PILOT-STATUS FORK (group SKD tracking)
//
// Upstream whatsmeow (sendGroup -> prepareMessageNode) encrypts the SenderKeyDistributionMessage
// (SKD) for every device of the group on every group message. For a group with ~800 devices that
// is ~800 Signal encryptions plus ~800 session writes per message, even though the SKD only has
// to reach each device once per sender key: afterwards the device decrypts our skmsg with the key
// it already has. WhatsApp Web and Baileys (src/Socket/messages-send.ts, "sender-key-memory") only
// send the SKD to devices that don't have it yet, and omit the <participants> node when nobody
// needs it.
//
// The state lives in store.SenderKeyDistributionStore. A device is considered to hold our key only
// when all of these are true, otherwise it gets the SKD again:
//   - it has an entry for the current sender key ID (a rotated key never matches older entries);
//   - it is still in the group's device list (entries of devices that left are pruned on send);
//   - its session and identity were not reset since (the sqlstore hooks delete the entry);
//   - it did not send a retry receipt for the group since (handleRetryReceipt deletes the entry);
//   - the entry is younger than skdRefreshInterval and fewer than skdRefreshIterations messages old,
//     so a device that silently lost the key (or missed more than libsignal's 2000-message
//     forward window) gets it back without depending on retry receipts.
//
// Entries are only written after the server acknowledged the message without an error.

import (
	"context"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

const (
	// skdRefreshInterval is how long a recorded SKD delivery is trusted.
	skdRefreshInterval = 7 * 24 * time.Hour
	// skdRefreshIterations is how many messages a recorded SKD delivery is trusted for.
	// libsignal refuses to skip more than 2000 message keys, so this stays well below that.
	skdRefreshIterations = 1000
)

// skdSendState carries the SKD tracking state of one group send from sendGroup to SendMessage.
type skdSendState struct {
	group     types.JID
	keyID     uint32
	iteration uint32

	// totalDevices is the number of devices in the group device list (excluding our own).
	totalDevices int
	// recipients are the devices the SKD was actually encrypted for in this send.
	recipients []types.JID
}

// skdHolds reports whether a stored state proves that the device holds the current sender key.
func skdHolds(state store.SKDState, ok bool, keyID, iteration uint32, now time.Time) bool {
	if !ok || state.KeyID != keyID || iteration < state.Iteration {
		return false
	}
	if iteration-state.Iteration >= skdRefreshIterations {
		return false
	}
	return now.Sub(state.SentAt) < skdRefreshInterval
}

// filterSKDTargets returns the subset of allDevices that must receive the SKD in this send.
// Any storage error falls back to all devices, like upstream.
func (cli *Client) filterSKDTargets(ctx context.Context, skd *skdSendState, allDevices []types.JID) []types.JID {
	ownJID := cli.getOwnID()
	ownLID := cli.getOwnLID()
	skd.totalDevices = 0
	for _, dev := range allDevices {
		if dev != ownJID && dev != ownLID {
			skd.totalDevices++
		}
	}
	known, err := cli.Store.SenderKeyDistribution.GetSKDRecipients(ctx, skd.group)
	if err != nil {
		cli.Log.Warnf("Failed to get sender key distribution state of %s, sending it to all devices: %v", skd.group, err)
		return allDevices
	}
	inGroup := make(map[types.JID]struct{}, len(allDevices))
	for _, dev := range allDevices {
		inGroup[dev] = struct{}{}
	}
	var stale []types.JID
	for dev := range known {
		if _, ok := inGroup[dev]; !ok {
			stale = append(stale, dev)
		}
	}
	if len(stale) > 0 {
		// The device left the group or was unlinked; if it comes back it must get the key again.
		if err = cli.Store.SenderKeyDistribution.DeleteSKDRecipients(ctx, skd.group, stale); err != nil {
			cli.Log.Warnf("Failed to prune sender key distribution state of %d devices in %s: %v", len(stale), skd.group, err)
		}
	}
	now := time.Now()
	targets := make([]types.JID, 0, len(allDevices))
	for _, dev := range allDevices {
		state, ok := known[dev]
		if !skdHolds(state, ok, skd.keyID, skd.iteration, now) {
			targets = append(targets, dev)
		}
	}
	return targets
}

// recordSKDRecipients extracts the devices that the SKD was encrypted for from the participant nodes.
func (skd *skdSendState) recordSKDRecipients(participantNodes []waBinary.Node) {
	skd.recipients = make([]types.JID, 0, len(participantNodes))
	for _, node := range participantNodes {
		if jid, ok := node.Attrs["jid"].(types.JID); ok {
			skd.recipients = append(skd.recipients, jid)
		}
	}
}

// commitSKDRecipients persists that this send's SKD recipients now hold the sender key.
// It must only be called after the server accepted the message.
func (cli *Client) commitSKDRecipients(ctx context.Context, skd *skdSendState) {
	if skd == nil || len(skd.recipients) == 0 || cli.Store.SenderKeyDistribution == nil {
		return
	}
	var pnDevices []types.JID
	for _, dev := range skd.recipients {
		if dev.Server == types.DefaultUserServer {
			pnDevices = append(pnDevices, dev)
		}
	}
	lids, err := cli.Store.LIDs.GetManyLIDsForPNs(ctx, pnDevices)
	if err != nil {
		// Without the session address, later session resets couldn't invalidate the entry.
		cli.Log.Warnf("Failed to get LIDs to record sender key distribution in %s: %v", skd.group, err)
		return
	}
	recipients := make([]store.SKDRecipient, len(skd.recipients))
	for i, dev := range skd.recipients {
		encryptionIdentity := dev
		if lid, ok := lids[dev]; ok && !lid.IsEmpty() {
			encryptionIdentity = lid
		}
		recipients[i] = store.SKDRecipient{Device: dev, Address: encryptionIdentity.SignalAddress().String()}
	}
	err = cli.Store.SenderKeyDistribution.PutSKDRecipients(ctx, skd.group, skd.keyID, skd.iteration, recipients)
	if err != nil {
		cli.Log.Warnf("Failed to record sender key distribution to %d devices in %s: %v", len(recipients), skd.group, err)
	}
}

// invalidateSKDForUser forgets every device of a user (in both its PN and LID forms) in all groups.
func (cli *Client) invalidateSKDForUser(ctx context.Context, user types.JID) {
	if cli.Store.SenderKeyDistribution == nil {
		return
	}
	users := []string{user.User}
	if alt, err := cli.Store.GetAltJID(ctx, user); err == nil && !alt.IsEmpty() {
		users = append(users, alt.User)
	}
	for _, u := range users {
		if err := cli.Store.SenderKeyDistribution.DeleteSKDRecipientsForUser(ctx, u); err != nil {
			cli.Log.Warnf("Failed to invalidate sender key distribution state of %s: %v", u, err)
		}
	}
}

// invalidateSKDForRetry forgets that a device holds our sender key for a group after it
// reported a decryption failure, so the next group message carries the SKD for it again
// (on top of the SKD that handleRetryReceipt includes in the resent message).
func (cli *Client) invalidateSKDForRetry(ctx context.Context, group, device types.JID) {
	if cli.Store.SenderKeyDistribution == nil || group.Server != types.GroupServer {
		return
	}
	devices := []types.JID{device}
	addresses := []string{device.SignalAddress().String()}
	if alt, err := cli.Store.GetAltJID(ctx, device); err != nil {
		cli.Log.Warnf("Failed to get alternate JID of %s to invalidate sender key distribution: %v", device, err)
	} else if !alt.IsEmpty() {
		alt.Device = device.Device
		devices = append(devices, alt)
		addresses = append(addresses, alt.SignalAddress().String())
	}
	if err := cli.Store.SenderKeyDistribution.DeleteSKDRecipients(ctx, group, devices); err != nil {
		cli.Log.Warnf("Failed to invalidate sender key distribution of %s in %s: %v", device, group, err)
	}
	if err := cli.Store.SenderKeyDistribution.DeleteSKDRecipientsByAddress(ctx, group, addresses); err != nil {
		cli.Log.Warnf("Failed to invalidate sender key distribution of %s in %s: %v", device, group, err)
	}
}
