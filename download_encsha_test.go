package whatsmeow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mau.fi/whatsmeow/util/cbcutil"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Media that carries a mediaKey but NO fileEncSHA256 is downloaded through the
// plaintext branch, and then validated as if it were encrypted.
//
// downloadPossiblyEncryptedMediaWithRetries decides "is this encrypted?" from
// `checksum == nil` — that is, from the presence of an INTEGRITY HASH, not from
// the presence of a KEY. With no checksum it calls downloadMedia, which returns
// the body whole and leaves `mac` nil, because downloadEncryptedMedia is the only
// place that splits the trailing mediaHMACLength bytes off. downloadAndDecrypt
// then skips its unencrypted branch (that one also requires `mediaKey == nil`)
// and hands the nil mac to validateMedia, which cannot match. Every host fails
// identically, retries do not help, and the error blames the media's HMAC when
// nothing was ever extracted to compare against.
//
// Measured in production on 2026-09-07, one number, one hour, images:
//
//	mediaKey  fileEncSHA256   total  lost  ok
//	absent    absent             38     0  38   <- genuinely unencrypted, works
//	present   absent              7     7   0   <- this test
//	present   present            72     0  72   <- normal path, works
//
// ⚠️ TestDownloadWithMediaKeyAndNoEncSHA256 is RED until the branch predicate is
// fixed, and that is deliberate: a test written to assert the current failure
// would go green today and red on the fix, which is backwards. The control below
// must stay green throughout — a red control means this harness is wrong, not the
// library.
//
// ⚠️ This file must live in whatsmeow/, the copy `go.mod` substitutes
// (`replace go.mau.fi/whatsmeow => ./whatsmeow`). whatsmeow-lib/ holds a newer
// copy that nothing builds and that carries the same defect; a test placed there
// compiles and proves nothing about what runs.

// mediaFixture is one encrypted media object as WhatsApp serves it: the AES-CBC
// ciphertext with the first mediaHMACLength bytes of the HMAC appended.
type mediaFixture struct {
	plaintext []byte
	body      []byte
	encSHA256 []byte
	sha256    []byte
	mediaKey  []byte
}

func newMediaFixture(t *testing.T) mediaFixture {
	t.Helper()

	plaintext := []byte("the bytes of an inbound image, long enough to span several AES blocks")
	mediaKey := make([]byte, 32)
	for i := range mediaKey {
		mediaKey[i] = byte(i)
	}

	iv, cipherKey, macKey, _ := getMediaKeys(mediaKey, MediaImage)
	ciphertext, err := cbcutil.Encrypt(cipherKey, iv, plaintext)
	if err != nil {
		t.Fatalf("encrypting the fixture failed: %v", err)
	}

	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	body := append(append([]byte{}, ciphertext...), h.Sum(nil)[:mediaHMACLength]...)

	encSum := sha256.Sum256(body)
	plainSum := sha256.Sum256(plaintext)

	return mediaFixture{
		plaintext: plaintext,
		body:      body,
		encSHA256: encSum[:],
		sha256:    plainSum[:],
		mediaKey:  mediaKey,
	}
}

func serveMedia(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func testClient() *Client {
	return &Client{Log: waLog.Noop, mediaHTTP: http.DefaultClient}
}

// The control. It exercises the same fixture, the same server and the same call
// through the branch that production takes 72 times out of 72, so a failure here
// means the fixture or the harness is wrong — never the predicate under test.
func TestDownloadWithEncSHA256Control(t *testing.T) {
	f := newMediaFixture(t)
	url := serveMedia(t, f.body)

	data, err := testClient().downloadAndDecrypt(
		context.Background(), url, f.mediaKey, MediaImage, f.encSHA256, f.sha256,
	)
	if err != nil {
		t.Fatalf("control failed, so the fixture is wrong and the sibling test proves nothing: %v", err)
	}
	if string(data) != string(f.plaintext) {
		t.Fatalf("control decrypted to %d bytes, want the original %d", len(data), len(f.plaintext))
	}
}

// The defect. Identical to the control except that fileEncSHA256 is nil, which is
// exactly what the failing production events carry: a mediaKey and no integrity
// hash. The bytes on the wire are byte-for-byte the same object the control
// decrypts, so any difference in outcome comes from the branch predicate alone.
func TestDownloadWithMediaKeyAndNoEncSHA256(t *testing.T) {
	f := newMediaFixture(t)
	url := serveMedia(t, f.body)

	data, err := testClient().downloadAndDecrypt(
		context.Background(), url, f.mediaKey, MediaImage, nil, f.sha256,
	)

	if errors.Is(err, ErrInvalidMediaHMAC) {
		t.Fatalf("media with a mediaKey and no fileEncSHA256 still fails with %v: "+
			"the download took the plaintext branch, so the trailing MAC was never split off "+
			"and validateMedia compared against nil", err)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(f.plaintext) {
		t.Fatalf("decrypted to %d bytes, want the original %d", len(data), len(f.plaintext))
	}
}
