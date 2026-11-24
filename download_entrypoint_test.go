package whatsmeow

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow/proto/waE2E"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// PILOT-STATUS FORK (download predicate). The other download tests call
// downloadAndDecrypt directly, so they cannot see what the PUBLIC entry point passes
// in. Upstream 72f22e6 made Download drop the mediaKey whenever fileEncSHA256 is
// absent, which silently re-broke the fork's fix for forwarded encrypted media while
// every lower-level test stayed green. These tests go through cli.Download, the call
// evolution-go makes, against a fake media host.
func entrypointClient(t *testing.T, body []byte) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	cli := &Client{Log: waLog.Noop, mediaHTTP: srv.Client()}
	cli.mediaConnCache = &MediaConn{
		TTL:       3600,
		FetchedAt: time.Now(),
		Hosts:     []MediaConnHost{{Hostname: strings.TrimPrefix(srv.URL, "https://")}},
	}
	return cli
}

// Forwarded media / media referencing an existing upload: mediaKey present, no
// fileEncSHA256, the blob IS encrypted.
func TestDownloadEntrypointEncryptedWithoutEncSHA256(t *testing.T) {
	f := newMediaFixture(t)
	cli := entrypointClient(t, f.body)
	msg := &waE2E.ImageMessage{
		DirectPath: proto.String("/v/t62.7118-24/fake?ccb=11-4"),
		MediaKey:   f.mediaKey,
		FileSHA256: f.sha256,
	}
	data, err := cli.Download(context.Background(), msg)
	if err != nil {
		t.Fatalf("encrypted media with a mediaKey and no fileEncSHA256 failed through Download: %v", err)
	}
	if !bytes.Equal(data, f.plaintext) {
		t.Fatalf("got %d bytes, want the %d original ones", len(data), len(f.plaintext))
	}
}

// Forwarded channel media: mediaKey present, no fileEncSHA256, the blob is PLAIN.
func TestDownloadEntrypointPlainChannelMediaWithMediaKey(t *testing.T) {
	f := newMediaFixture(t)
	cli := entrypointClient(t, f.plaintext)
	msg := &waE2E.ImageMessage{
		DirectPath: proto.String("/v/t62.7118-24/fake?ccb=11-4"),
		MediaKey:   f.mediaKey,
		FileSHA256: f.sha256,
	}
	data, err := cli.Download(context.Background(), msg)
	if err != nil {
		t.Fatalf("plain channel media with a mediaKey failed through Download: %v", err)
	}
	if !bytes.Equal(data, f.plaintext) {
		t.Fatalf("got %d bytes, want the %d original ones", len(data), len(f.plaintext))
	}
}
