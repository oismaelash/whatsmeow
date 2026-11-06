package whatsmeow

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"go.mau.fi/util/exsync"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// recordingLogger keeps every formatted line so tests can assert on content.
type recordingLogger struct {
	mu    *sync.Mutex
	lines *[]string
}

func newRecordingLogger() recordingLogger {
	return recordingLogger{mu: &sync.Mutex{}, lines: &[]string{}}
}

func (r recordingLogger) add(level, msg string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.lines = append(*r.lines, level+" "+fmt.Sprintf(msg, args...))
}
func (r recordingLogger) Errorf(msg string, args ...any) { r.add("ERROR", msg, args...) }
func (r recordingLogger) Warnf(msg string, args ...any)  { r.add("WARN", msg, args...) }
func (r recordingLogger) Infof(msg string, args ...any)  { r.add("INFO", msg, args...) }
func (r recordingLogger) Debugf(msg string, args ...any) { r.add("DEBUG", msg, args...) }
func (r recordingLogger) Sub(string) waLog.Logger        { return r }
func (r recordingLogger) joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(*r.lines, "\n")
}

func TestEmitQRsDoesNotLogTheCode(t *testing.T) {
	const code = "2@QRREFSECRET,NOISEPUBSECRET=,IDENTITYPUBSECRET=,ADVSECRET="
	rec := newRecordingLogger()
	output := make(chan QRChannelItem, 1)
	stop := make(chan struct{})
	close(stop) // return right after the first code is emitted
	qrc := &qrChannel{
		cli:     &Client{expectedDisconnect: exsync.NewEvent()},
		log:     rec,
		ctx:     context.Background(),
		output:  output,
		stopQRs: stop,
	}

	qrc.emitQRs([]string{code, "2@second", "2@third", "2@fourth", "2@fifth", "2@sixth"})

	item := <-output
	if item.Code != code || item.Event != QRChannelEventCode {
		t.Fatalf("QR channel must still deliver the code, got %+v", item)
	}
	out := rec.joined()
	for _, secret := range []string{code, "QRREFSECRET", "ADVSECRET"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log leaks QR material %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, fmt.Sprintf("Emitting QR code (length: %d, timeout: 1m0s, remaining: 5)", len(code))) {
		t.Fatalf("event line missing:\n%s", out)
	}
}
