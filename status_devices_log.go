package whatsmeow

// PILOT-STATUS FORK (status diagnostics)

import (
	"fmt"
	"sort"
	"strings"

	"go.mau.fi/whatsmeow/types"
)

// summarizeDevices renders "N devices of M users: user=[0,2] ..." sorted by user, so a
// participant-hash mismatch on a story shows which devices we actually encrypted for.
func summarizeDevices(devices []types.JID) string {
	byUser := map[string][]int{}
	for _, d := range devices {
		key := d.User + "@" + d.Server
		byUser[key] = append(byUser[key], int(d.Device))
	}
	users := make([]string, 0, len(byUser))
	for u := range byUser {
		users = append(users, u)
	}
	sort.Strings(users)
	parts := make([]string, 0, len(users))
	for _, u := range users {
		ds := byUser[u]
		sort.Ints(ds)
		parts = append(parts, fmt.Sprintf("%s=%v", u, ds))
	}
	return fmt.Sprintf("%d devices of %d users: %s", len(devices), len(users), strings.Join(parts, " "))
}
