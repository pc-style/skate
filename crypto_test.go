package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/spf13/cobra"
)

func TestEncryptValueRoundTrip(t *testing.T) {
	envelope, dataKey, err := newKeyEnvelope("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	unlocked, err := unlockDataKey(envelope, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dataKey, unlocked) {
		t.Fatal("unlocked data key did not match generated key")
	}
	itemKey := []byte("token")
	encrypted, err := encryptValue(dataKey, itemKey, []byte("agent secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("agent secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	plaintext, err := decryptValue(unlocked, itemKey, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "agent secret" {
		t.Fatalf("got %q, want %q", plaintext, "agent secret")
	}
}

func TestUnlockDataKeyRejectsWrongPassphrase(t *testing.T) {
	envelope, _, err := newKeyEnvelope("right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unlockDataKey(envelope, "wrong"); err == nil {
		t.Fatal("wrong passphrase unlocked the database")
	}
}

func TestSessionExpires(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SKATE_SESSION_DIR", dir)
	session := sessionFile{
		Version:    sessionVersion,
		DB:         "agent",
		EnvelopeFP: "fp",
		DataKey:    "AAAA",
		ExpiresAt:  time.Now().Add(-time.Hour),
	}
	bts, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionPath(dir, "agent"), bts, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSession("agent", "fp"); err == nil {
		t.Fatal("expired session loaded successfully")
	}
}

func TestEncryptDBMigratesPlaintextValues(t *testing.T) {
	t.Setenv("SKATE_DATA_DIR", t.TempDir())
	t.Setenv("SKATE_SESSION_DIR", t.TempDir())
	passphraseStdin = true
	passphraseEnv = ""
	dryRun = false
	sessionTTL = defaultSessionTTL
	t.Cleanup(func() {
		passphraseStdin = false
		passphraseEnv = ""
		dryRun = false
		sessionTTL = defaultSessionTTL
	})
	func() {
		db, err := openKV("legacy")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		}()
		if err := wrap(db, false, func(tx *badger.Txn) error {
			return tx.Set([]byte("token"), []byte("old-secret"))
		}); err != nil {
			t.Fatal(err)
		}
	}()
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("migration-passphrase\n"))
	if err := encryptDB(cmd, []string{"@legacy"}); err != nil {
		t.Fatal(err)
	}
	db, err := openKV("legacy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	var stored []byte
	if err := wrap(db, true, func(tx *badger.Txn) error {
		item, err := tx.Get([]byte("token"))
		if err != nil {
			return err
		}
		stored, err = item.ValueCopy(nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("old-secret")) {
		t.Fatal("migrated value still contains plaintext")
	}
	dataKey, err := dataKeyForDB(cmd, db, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptValue(dataKey, []byte("token"), stored)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "old-secret" {
		t.Fatalf("got %q, want %q", plaintext, "old-secret")
	}
}
