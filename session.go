package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sessionVersion    = 1
	defaultSessionTTL = 12 * time.Hour
)

type sessionFile struct {
	Version   int       `json:"version"`
	DB        string    `json:"db"`
	DataKey   string    `json:"data_key"`
	ExpiresAt time.Time `json:"expires_at"`
}

func saveSession(dbName string, dataKey []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	dir := getSessionDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	session := sessionFile{
		Version:   sessionVersion,
		DB:        dbName,
		DataKey:   base64.StdEncoding.EncodeToString(dataKey),
		ExpiresAt: time.Now().Add(ttl),
	}
	bts, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	path := sessionPath(dir, dbName)
	if err := os.WriteFile(path, bts, 0o600); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return nil
}

func loadSession(dbName string) ([]byte, error) {
	dir := getSessionDir()
	bts, err := os.ReadFile(sessionPath(dir, dbName))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("database @%s is locked; run `skate unlock @%s --passphrase-stdin` once for this session", dbName, dbName)
	}
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	var session sessionFile
	if err := json.Unmarshal(bts, &session); err != nil {
		return nil, fmt.Errorf("parse session: %w", err)
	}
	if session.Version != sessionVersion || session.DB != dbName {
		return nil, fmt.Errorf("session for @%s is invalid; run `skate unlock @%s --passphrase-stdin`", dbName, dbName)
	}
	if time.Now().After(session.ExpiresAt) {
		_ = removeSession(dbName)
		return nil, fmt.Errorf("session for @%s expired; run `skate unlock @%s --passphrase-stdin`", dbName, dbName)
	}
	dataKey, err := base64.StdEncoding.DecodeString(session.DataKey)
	if err != nil {
		return nil, fmt.Errorf("decode session key: %w", err)
	}
	if len(dataKey) != dataKeySize {
		return nil, fmt.Errorf("session for @%s has an invalid key", dbName)
	}
	return dataKey, nil
}

func removeSession(dbName string) error {
	dir := getSessionDir()
	if err := os.Remove(sessionPath(dir, dbName)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove session: %w", err)
	}
	return nil
}

func sessionStatus(dbName string) string {
	_, err := loadSession(dbName)
	if err == nil {
		return "unlocked"
	}
	return "locked"
}

func getSessionDir() string {
	if dir := os.Getenv("SKATE_SESSION_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "skate")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("skate-%d", os.Getuid()))
}

func sessionPath(dir, dbName string) string {
	name := strings.NewReplacer("/", "_", "\\", "_", ":", "_", string(filepath.Separator), "_").Replace(dbName)
	return filepath.Join(dir, name+".json")
}
