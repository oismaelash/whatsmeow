package whatsmeow

import (
	"testing"

	"go.mau.fi/whatsmeow/types"
)

func TestSummarizeDevices(t *testing.T) {
	got := summarizeDevices([]types.JID{
		types.NewADJID("5511", 0, 2),
		types.NewADJID("5511", 0, 0),
		types.NewADJID("5521", 0, 0),
	})
	want := "3 devices of 2 users: 5511@s.whatsapp.net=[0 2] 5521@s.whatsapp.net=[0]"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
