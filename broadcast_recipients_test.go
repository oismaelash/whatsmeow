// PILOT-STATUS FORK (status recipients): tests for SendRequestExtra.BroadcastRecipients.

package whatsmeow

import (
	"testing"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

func newClientWithOwnID(own types.JID) *Client {
	dev := &store.Device{ID: &own}
	return &Client{Store: dev}
}

func TestExplicitBroadcastParticipantsDedupesAndAddsOwnID(t *testing.T) {
	own := types.NewADJID("5511900000000", 0, 3)
	cli := newClientWithOwnID(own)
	a := types.NewJID("5511999999999", types.DefaultUserServer)
	aDevice := types.NewADJID("5511999999999", 0, 5)
	b := types.NewJID("5521988887777", types.DefaultUserServer)

	got, err := cli.explicitBroadcastParticipants([]types.JID{a, aDevice, b, a})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []types.JID{a, b, own.ToNonAD()}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestExplicitBroadcastParticipantsKeepsOwnIDOnce(t *testing.T) {
	own := types.NewJID("5511900000000", types.DefaultUserServer)
	cli := newClientWithOwnID(own)
	got, err := cli.explicitBroadcastParticipants([]types.JID{own})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != own {
		t.Fatalf("got %v, want [%v]", got, own)
	}
}

func TestExplicitBroadcastParticipantsRequiresLogin(t *testing.T) {
	cli := &Client{Store: &store.Device{}}
	if _, err := cli.explicitBroadcastParticipants([]types.JID{types.NewJID("1", types.DefaultUserServer)}); err != ErrNotLoggedIn {
		t.Fatalf("got %v, want ErrNotLoggedIn", err)
	}
}
