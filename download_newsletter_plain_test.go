package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// A forward of CHANNEL (newsletter) media: the blob is served IN CLEAR, yet the message
// carries a mediaKey and no fileEncSHA256. Measured 05/11/2026 as 96% of the inbound
// media losses of one number. Before this fix the `mediaKey != nil` predicate split the
// last 10 bytes off as a MAC and the HMAC failed on every host.
func TestDownloadClearNewsletterMediaWithMediaKey(t *testing.T) {
	f := newMediaFixture(t)
	url := serveMedia(t, f.plaintext)

	data, err := testClient().downloadAndDecrypt(
		context.Background(), url, f.mediaKey, MediaImage, nil, sha256Sum(f.plaintext),
	)
	if err != nil {
		t.Fatalf("clear channel media with a mediaKey still fails: %v", err)
	}
	if !bytes.Equal(data, f.plaintext) {
		t.Fatalf("got %d bytes, want the %d original ones", len(data), len(f.plaintext))
	}
}

// The fallback must never return CIPHERTEXT as media: a really encrypted blob whose MAC
// is wrong cannot hash to its own plaintext, so the HMAC error stands.
func TestEncryptedMediaWithBadMACStillFails(t *testing.T) {
	f := newMediaFixture(t)
	corrupted := append([]byte{}, f.body...)
	corrupted[len(corrupted)-1] ^= 0xff
	url := serveMedia(t, corrupted)

	_, err := testClient().downloadAndDecrypt(
		context.Background(), url, f.mediaKey, MediaImage, nil, sha256Sum(f.plaintext),
	)
	if !errors.Is(err, ErrInvalidMediaHMAC) {
		t.Fatalf("want ErrInvalidMediaHMAC for encrypted media with a bad MAC, got %v", err)
	}
}

// Clear bytes that do NOT match fileSHA256 are not accepted either.
func TestClearMediaWithWrongHashStillFails(t *testing.T) {
	f := newMediaFixture(t)
	url := serveMedia(t, f.plaintext)
	wrong := sha256Sum([]byte("something else"))

	_, err := testClient().downloadAndDecrypt(
		context.Background(), url, f.mediaKey, MediaImage, nil, wrong,
	)
	if !errors.Is(err, ErrInvalidMediaHMAC) {
		t.Fatalf("want ErrInvalidMediaHMAC when the clear bytes do not match fileSHA256, got %v", err)
	}
}
