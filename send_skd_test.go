// PILOT-STATUS FORK (group SKD tracking): tests for sending the sender key distribution
// message only to the devices that don't hold our current sender key.

package whatsmeow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/util/optional"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
)

// memStore is an in-memory implementation of the stores that a group send touches.
// Everything else falls through to NoopStore and returns an error.
type memStore struct {
	*store.NoopStore

	mu         sync.Mutex
	identities map[string][32]byte
	sessions   map[string][]byte
	senderKeys map[string][]byte
	skd        map[string]map[types.JID]memSKDEntry

	encryptedSessionWrites int
}

type memSKDEntry struct {
	state   store.SKDState
	address string
}

var _ store.AllSessionSpecificStores = (*memStore)(nil)
var _ store.SenderKeyDistributionStore = (*memStore)(nil)
var _ store.LIDStore = (*memStore)(nil)

func newMemStore() *memStore {
	return &memStore{
		NoopStore:  &store.NoopStore{Error: errors.New("not implemented in memStore")},
		identities: make(map[string][32]byte),
		sessions:   make(map[string][]byte),
		senderKeys: make(map[string][]byte),
		skd:        make(map[string]map[types.JID]memSKDEntry),
	}
}

func (m *memStore) PutIdentity(_ context.Context, address string, key [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identities[address] = key
	return nil
}

func (m *memStore) IsTrustedIdentity(_ context.Context, address string, key [32]byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.identities[address]
	return !ok || existing == key, nil
}

func (m *memStore) GetSession(_ context.Context, address string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[address], nil
}

func (m *memStore) HasSession(_ context.Context, address string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.sessions[address]
	return ok, nil
}

func (m *memStore) GetManySessions(_ context.Context, addresses []string) (map[string][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(addresses))
	for _, addr := range addresses {
		out[addr] = m.sessions[addr]
	}
	return out, nil
}

func (m *memStore) PutSession(_ context.Context, address string, session []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[address] = session
	return nil
}

func (m *memStore) PutManySessions(_ context.Context, sessions map[string][]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for addr, sess := range sessions {
		m.sessions[addr] = sess
	}
	m.encryptedSessionWrites += len(sessions)
	return nil
}

func (m *memStore) PutSenderKey(_ context.Context, group, user string, session []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.senderKeys[group+"|"+user] = session
	return nil
}

func (m *memStore) GetSenderKey(_ context.Context, group, user string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.senderKeys[group+"|"+user], nil
}

func (m *memStore) deleteAllSenderKeys() {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.senderKeys)
}

func (m *memStore) GetSKDRecipients(_ context.Context, group types.JID) (map[types.JID]store.SKDState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[types.JID]store.SKDState)
	for dev, entry := range m.skd[group.String()] {
		out[dev] = entry.state
	}
	return out, nil
}

func (m *memStore) PutSKDRecipients(_ context.Context, group types.JID, keyID, iteration uint32, recipients []store.SKDRecipient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, ok := m.skd[group.String()]
	if !ok {
		entries = make(map[types.JID]memSKDEntry)
		m.skd[group.String()] = entries
	}
	for _, r := range recipients {
		entries[r.Device] = memSKDEntry{
			state:   store.SKDState{KeyID: keyID, Iteration: iteration, SentAt: time.Now()},
			address: r.Address,
		}
	}
	return nil
}

func (m *memStore) DeleteSKDRecipients(_ context.Context, group types.JID, devices []types.JID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, dev := range devices {
		delete(m.skd[group.String()], dev)
	}
	return nil
}

func (m *memStore) DeleteSKDRecipientsByAddress(_ context.Context, group types.JID, addresses []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for chat, entries := range m.skd {
		if !group.IsEmpty() && chat != group.String() {
			continue
		}
		for dev, entry := range entries {
			for _, addr := range addresses {
				if entry.address == addr {
					delete(entries, dev)
				}
			}
		}
	}
	return nil
}

func (m *memStore) DeleteSKDRecipientsForUser(_ context.Context, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entries := range m.skd {
		for dev, entry := range entries {
			if strings.HasPrefix(entry.address, user+":") || strings.HasPrefix(entry.address, user+"_") {
				delete(entries, dev)
			}
		}
	}
	return nil
}

func (m *memStore) DeleteAllSKDRecipients(_ context.Context, group types.JID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.skd, group.String())
	return nil
}

func (m *memStore) skdCount(group types.JID) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.skd[group.String()])
}

func (m *memStore) GetManyLIDsForPNs(_ context.Context, _ []types.JID) (map[types.JID]types.JID, error) {
	return map[types.JID]types.JID{}, nil
}

func (m *memStore) GetLIDForPN(_ context.Context, _ types.JID) (types.JID, error) {
	return types.EmptyJID, nil
}

func (m *memStore) GetPNForLID(_ context.Context, _ types.JID) (types.JID, error) {
	return types.EmptyJID, nil
}

type skdTestEnv struct {
	t     *testing.T
	ctx   context.Context
	cli   *Client
	mem   *memStore
	group types.JID
	users []types.JID
	seq   int
}

func newSKDTestEnv(t *testing.T) *skdTestEnv {
	t.Helper()
	mem := newMemStore()
	ownPN := types.NewADJID("5511900000000", 0, 7)
	ownLID := types.NewADJID("990000000000001", 0, 7)
	ownLID.Server = types.HiddenUserServer
	device := &store.Device{
		ID:             &ownPN,
		LID:            ownLID,
		IdentityKey:    keys.NewKeyPair(),
		NoiseKey:       keys.NewKeyPair(),
		RegistrationID: 1234,
		Initialized:    true,
		Container:      mem,
	}
	device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(1)
	device.SetAllStores(mem)
	device.LIDs = mem
	cli := NewClient(device, nil)
	return &skdTestEnv{
		t:     t,
		ctx:   context.Background(),
		cli:   cli,
		mem:   mem,
		group: types.NewJID("120363409843570232", types.GroupServer),
	}
}

// addUser adds a group participant with the given number of devices, each with an
// established Signal session (as if its prekey bundle had been fetched before).
func (env *skdTestEnv) addUser(deviceCount int) types.JID {
	env.t.Helper()
	env.seq++
	user := types.NewJID(fmt.Sprintf("10000000000%04d", env.seq), types.HiddenUserServer)
	devices := make([]types.JID, deviceCount)
	for i := range devices {
		dev := user
		dev.Device = uint16(i)
		devices[i] = dev
		env.establishSession(dev)
	}
	env.cli.userDevicesCacheLock.Lock()
	env.cli.userDevicesCache[user] = deviceCache{devices: devices, dhash: participantListHashV2(devices)}
	env.cli.userDevicesCacheLock.Unlock()
	env.users = append(env.users, user)
	return user
}

func (env *skdTestEnv) establishSession(dev types.JID) {
	env.t.Helper()
	identityKey := keys.NewKeyPair()
	signedPreKey := identityKey.CreateSignedPreKey(1)
	preKey := keys.NewPreKey(2)
	bundle := prekey.NewBundle(42, uint32(dev.Device),
		optional.NewOptionalUint32(preKey.KeyID), signedPreKey.KeyID,
		ecc.NewDjbECPublicKey(*preKey.Pub), ecc.NewDjbECPublicKey(*signedPreKey.Pub), *signedPreKey.Signature,
		identity.NewKey(ecc.NewDjbECPublicKey(*identityKey.Pub)))
	builder := session.NewBuilderFromSignal(env.cli.Store, dev.SignalAddress(), pbSerializer)
	if err := builder.ProcessBundle(env.ctx, bundle); err != nil {
		env.t.Fatalf("failed to establish session with %s: %v", dev, err)
	}
}

func (env *skdTestEnv) removeUser(user types.JID) {
	for i, u := range env.users {
		if u == user {
			env.users = append(env.users[:i], env.users[i+1:]...)
			return
		}
	}
}

// send builds the group message node like sendGroup does, then simulates the server ack
// the way SendMessage handles it. It returns the devices the SKD was encrypted for.
func (env *skdTestEnv) send(ack bool) ([]types.JID, *waBinary.Node) {
	env.t.Helper()
	skd := &skdSendState{}
	var timings MessageDebugTimings
	_, node, err := env.cli.prepareGroupMessageNode(
		env.ctx, env.cli.getOwnLID(), env.group, env.users, env.cli.GenerateMessageID(),
		&waE2E.Message{Conversation: proto.String("hello")}, &timings, nodeExtraParams{skd: skd},
	)
	if err != nil {
		env.t.Fatalf("failed to prepare group message: %v", err)
	}
	if ack {
		env.cli.commitSKDRecipients(env.ctx, skd)
	}
	var recipients []types.JID
	participants, ok := node.GetOptionalChildByTag("participants")
	if ok {
		for _, child := range participants.GetChildren() {
			recipients = append(recipients, child.AttrGetter().JID("jid"))
		}
	}
	if _, ok := node.GetOptionalChildByTag("enc"); !ok {
		env.t.Fatalf("group message node has no skmsg: %s", node.String())
	}
	return recipients, node
}

func (env *skdTestEnv) devicesOf(user types.JID) []types.JID {
	env.cli.userDevicesCacheLock.Lock()
	defer env.cli.userDevicesCacheLock.Unlock()
	return env.cli.userDevicesCache[user].devices
}

func assertRecipients(t *testing.T, got []types.JID, want ...types.JID) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("SKD sent to %d devices (%v), want %d (%v)", len(got), got, len(want), want)
	}
	wantSet := make(map[types.JID]struct{}, len(want))
	for _, w := range want {
		wantSet[w] = struct{}{}
	}
	for _, g := range got {
		if _, ok := wantSet[g]; !ok {
			t.Fatalf("SKD unexpectedly sent to %s (got %v, want %v)", g, got, want)
		}
	}
}

func TestGroupSendDistributesSenderKeyOnlyOnce(t *testing.T) {
	env := newSKDTestEnv(t)
	for range 20 {
		env.addUser(2)
	}

	first, _ := env.send(true)
	if len(first) != 40 {
		t.Fatalf("first send: SKD sent to %d devices, want all 40", len(first))
	}
	writesAfterFirst := env.mem.encryptedSessionWrites

	second, node := env.send(true)
	assertRecipients(t, second)
	if _, ok := node.GetOptionalChildByTag("participants"); ok {
		t.Fatalf("second send still has a participants node: %s", node.String())
	}
	if _, ok := node.GetOptionalChildByTag("device-identity"); ok {
		t.Fatalf("second send includes device-identity without any pkmsg")
	}
	if node.AttrGetter().String("phash") == "" {
		t.Fatalf("second send lost the participant hash")
	}
	if writes := env.mem.encryptedSessionWrites - writesAfterFirst; writes != 0 {
		t.Fatalf("second send wrote %d sessions, want 0", writes)
	}
}

func TestGroupSendWithoutAckDoesNotRecordRecipients(t *testing.T) {
	env := newSKDTestEnv(t)
	env.addUser(2)
	env.addUser(1)

	first, _ := env.send(false)
	if len(first) != 3 {
		t.Fatalf("first send: SKD sent to %d devices, want 3", len(first))
	}
	second, _ := env.send(true)
	if len(second) != 3 {
		t.Fatalf("send after an unacknowledged one: SKD sent to %d devices, want 3 again", len(second))
	}
}

func TestGroupSendNewParticipantAndNewDeviceGetSenderKey(t *testing.T) {
	env := newSKDTestEnv(t)
	alice := env.addUser(1)
	env.addUser(2)
	env.send(true)

	bob := env.addUser(2)
	got, _ := env.send(true)
	assertRecipients(t, got, env.devicesOf(bob)...)

	// Alice links a new companion device.
	newDevice := alice
	newDevice.Device = 3
	env.establishSession(newDevice)
	env.cli.userDevicesCacheLock.Lock()
	cached := env.cli.userDevicesCache[alice]
	cached.devices = append(append([]types.JID{}, cached.devices...), newDevice)
	env.cli.userDevicesCache[alice] = cached
	env.cli.userDevicesCacheLock.Unlock()
	got, _ = env.send(true)
	assertRecipients(t, got, newDevice)

	got, _ = env.send(true)
	assertRecipients(t, got)
}

func TestGroupSendParticipantThatLeftAndCameBackGetsSenderKeyAgain(t *testing.T) {
	env := newSKDTestEnv(t)
	alice := env.addUser(2)
	env.addUser(1)
	env.send(true)

	env.removeUser(alice)
	got, _ := env.send(true)
	assertRecipients(t, got)
	if n := env.mem.skdCount(env.group); n != 1 {
		t.Fatalf("devices of a participant that left were not pruned: %d entries, want 1", n)
	}

	env.users = append(env.users, alice)
	got, _ = env.send(true)
	assertRecipients(t, got, env.devicesOf(alice)...)
}

func TestRetryReceiptResendsSenderKeyToThatDevice(t *testing.T) {
	env := newSKDTestEnv(t)
	alice := env.addUser(2)
	env.addUser(2)
	env.send(true)

	failing := env.devicesOf(alice)[1]
	receipt := &events.Receipt{
		MessageSource: types.MessageSource{
			Chat:    env.group,
			Sender:  failing,
			IsGroup: true,
		},
		Type: types.ReceiptTypeRetry,
	}
	node := &waBinary.Node{
		Tag: "receipt",
		Content: []waBinary.Node{{
			Tag:   "retry",
			Attrs: waBinary.Attrs{"id": "UNKNOWNMESSAGEID", "t": "1793000000", "count": "1"},
		}},
	}
	// The message is not in the retry cache, so the retry itself fails: the device must
	// still get the SKD with the next group message.
	if err := env.cli.handleRetryReceipt(env.ctx, receipt, node); err == nil {
		t.Fatalf("expected the retry of an unknown message to fail")
	}
	got, _ := env.send(true)
	assertRecipients(t, got, failing)

	got, _ = env.send(true)
	assertRecipients(t, got)
}

func TestSenderKeyRotationResetsDistributionState(t *testing.T) {
	env := newSKDTestEnv(t)
	env.addUser(2)
	env.addUser(3)
	first, _ := env.send(true)
	if len(first) != 5 {
		t.Fatalf("first send: SKD sent to %d devices, want 5", len(first))
	}

	// Losing our sender key record makes libsignal create a new key with a new ID.
	env.mem.deleteAllSenderKeys()
	got, _ := env.send(true)
	if len(got) != 5 {
		t.Fatalf("after rotation: SKD sent to %d devices, want all 5", len(got))
	}
	got, _ = env.send(true)
	assertRecipients(t, got)
}

func TestIdentityChangeInvalidatesSenderKeyDistribution(t *testing.T) {
	env := newSKDTestEnv(t)
	alice := env.addUser(2)
	env.addUser(1)
	env.send(true)

	env.cli.invalidateSKDForUser(env.ctx, alice)
	got, _ := env.send(true)
	assertRecipients(t, got, env.devicesOf(alice)...)
}

func TestSKDHoldsRefreshesOldEntries(t *testing.T) {
	now := time.Now()
	fresh := store.SKDState{KeyID: 7, Iteration: 10, SentAt: now.Add(-time.Hour)}
	cases := []struct {
		name      string
		state     store.SKDState
		ok        bool
		keyID     uint32
		iteration uint32
		want      bool
	}{
		{"unknown device", store.SKDState{}, false, 7, 10, false},
		{"same key", fresh, true, 7, 11, true},
		{"rotated key", fresh, true, 8, 11, false},
		{"iteration went back", fresh, true, 7, 9, false},
		{"too many messages since", fresh, true, 7, 10 + skdRefreshIterations, false},
		{"just under the iteration limit", fresh, true, 7, 10 + skdRefreshIterations - 1, true},
		{"too old", store.SKDState{KeyID: 7, Iteration: 10, SentAt: now.Add(-skdRefreshInterval)}, true, 7, 11, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := skdHolds(tc.state, tc.ok, tc.keyID, tc.iteration, now); got != tc.want {
				t.Fatalf("skdHolds() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGroupSendWithoutSKDStoreSendsToEveryone(t *testing.T) {
	env := newSKDTestEnv(t)
	env.cli.Store.SenderKeyDistribution = nil
	env.addUser(2)
	env.addUser(1)
	first, _ := env.send(true)
	second, _ := env.send(true)
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("without the store every send must carry the SKD for all 3 devices, got %d and %d", len(first), len(second))
	}
}
