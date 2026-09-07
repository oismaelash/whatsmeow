package whatsmeow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

// O SEGUNDO DEFEITO, e produzia o MESMO texto de erro que o primeiro.
//
// ⛔ Uma mensagem SEM `mediaKey` mas COM `fileEncSHA256` nao escapava pelo ramo
// "nao cifrado" — o escape exigia que os TRES fossem nil. Caia no `validateMedia`,
// que derivava um `macKey` de uma chave NULA (`getMediaKeys(nil, ...)` corre e
// devolve bytes) e comparava contra ele. Falhava sempre, com `ErrInvalidMediaHMAC`.
//
// ⚠️ Isso tornava os dois defeitos INDISTINGUIVEIS no log: mesmo erro, causas
// opostas — um por ter chave e nao ter hash, o outro por ter hash e nao ter chave.
// Quem investigasse pelo texto do erro juntava-os numa causa so.
func TestDownloadWithoutMediaKeyButWithEncSHA256(t *testing.T) {
	f := newMediaFixture(t)
	// Sem chave, o que se serve sao bytes CLAROS — e a `fileSHA256` e a deles.
	url := serveMedia(t, f.plaintext)

	data, err := testClient().downloadAndDecrypt(
		context.Background(), url, nil, MediaImage, f.encSHA256, sha256Sum(f.plaintext),
	)

	if errors.Is(err, ErrInvalidMediaHMAC) {
		t.Fatalf("media sem mediaKey ainda falha com %v: o escape exigia os tres nil, "+
			"entao a media sem chave mas com hash caia no validateMedia e este derivava "+
			"um macKey de uma chave nula", err)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(data, f.plaintext) {
		t.Fatalf("devolveu %d bytes, queria os %d originais", len(data), len(f.plaintext))
	}
}

// Helper local: o hash dos bytes CLAROS, que e o que `fileSHA256` significa.
func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
