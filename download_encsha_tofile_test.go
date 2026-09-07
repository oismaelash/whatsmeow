package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// O CAMINHO PARALELO, e existe porque metade do conserto estava sem defesa.
//
// ⛔ `downloadAndDecryptToFile` é um gémeo completo de `downloadAndDecrypt`: outra
// função, outro helper (`downloadPossiblyEncryptedMediaWithRetriesToFile`), outra
// guarda de checksum — e tinha o MESMO predicado errado. O teste irmão, em
// `download_encsha_test.go`, só exercita o caminho em memória; um `revert` que
// desfizesse apenas este lado deixaria a perda de média viva e a suíte verde.
//
// A fixture e o servidor são partilhados com o teste irmão de propósito: os bytes
// na rede são os mesmos objectos, portanto qualquer diferença de desfecho vem do
// predicado do ramo e de mais nada.

// Escreve num ficheiro temporário real em vez de um buffer: a assinatura pede um
// `File` (Seek + Truncate + Write), e um stub que os ignore esconderia justamente
// o `Seek(0)` que a retentativa faz entre tentativas.
func tempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "media-*")
	if err != nil {
		t.Fatalf("could not create the temp file the download writes into: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func readAll(t *testing.T, f *os.File) []byte {
	t.Helper()
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		t.Fatalf("read back: %v", err)
	}
	return buf.Bytes()
}

// Controlo: com `fileEncSHA256`, este caminho sempre funcionou. Passa antes e
// depois do conserto — se ALGUM dia falhar, o problema é a fixture, não a lib.
func TestDownloadToFileWithEncSHA256Control(t *testing.T) {
	f := newMediaFixture(t)
	url := serveMedia(t, f.body)
	out := tempFile(t)

	err := testClient().downloadAndDecryptToFile(
		context.Background(), url, f.mediaKey, MediaImage, f.encSHA256, f.sha256, out,
	)
	if err != nil {
		t.Fatalf("control failed, so the fixture is wrong and the sibling test proves nothing: %v", err)
	}
	if got := readAll(t, out); !bytes.Equal(got, f.plaintext) {
		t.Fatalf("control wrote %d bytes, want the original %d", len(got), len(f.plaintext))
	}
}

// O defeito, no caminho que escreve em ficheiro. Idêntico ao controlo excepto o
// `fileEncSHA256` nil — que é o que os eventos que falham em produção carregam.
func TestDownloadToFileWithMediaKeyAndNoEncSHA256(t *testing.T) {
	f := newMediaFixture(t)
	url := serveMedia(t, f.body)
	out := tempFile(t)

	err := testClient().downloadAndDecryptToFile(
		context.Background(), url, f.mediaKey, MediaImage, nil, f.sha256, out,
	)

	if errors.Is(err, ErrInvalidMediaHMAC) {
		t.Fatalf("the to-file path still fails with %v: it took the plaintext branch, "+
			"so the trailing MAC was never split off and validateMedia compared against nil", err)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ⛔ E o ficheiro tem de conter o PLAINTEXT. Sem esta asserção o teste passaria
	// com o MAC ainda colado ao fim dos bytes — que é a média corrompida em silêncio,
	// pior do que a perda que este conserto fecha.
	if got := readAll(t, out); !bytes.Equal(got, f.plaintext) {
		t.Fatalf("wrote %d bytes, want the original %d — the MAC was probably left in", len(got), len(f.plaintext))
	}
}
