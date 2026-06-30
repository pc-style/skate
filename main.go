// Package main provides the skate CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/agnivade/levenshtein"
	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/lipgloss"
	"github.com/dgraph-io/badger/v4"
	gap "github.com/muesli/go-app-paths"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	reverseIterate   bool
	keysIterate      bool
	valuesIterate    bool
	showBinary       bool
	delimiterIterate string
	passphraseEnv    string
	passphraseStdin  bool
	initEncryptedDB  bool
	sessionTTL       time.Duration
	assumeYes        bool
	dryRun           bool

	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("204")).Bold(true)

	rootCmd = &cobra.Command{
		Use:     "skate",
		Short:   "Skate, an encrypted personal key value store.",
		Example: "  skate unlock @agent --init --passphrase-stdin\n  skate set token@agent \"$TOKEN\"\n  skate get token@agent\n  skate lock @agent",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	setCmd = &cobra.Command{
		Use:     "set KEY[@DB] [VALUE]",
		Short:   "Set a value for a key with an optional @ db. If VALUE is omitted, read value from the standard input.",
		Example: "  skate set foo@agent bar\n  skate set foo@agent <./bar.txt",
		Args:    cobra.RangeArgs(1, 2),
		RunE:    set,
	}

	getCmd = &cobra.Command{
		Use:           "get KEY[@DB]",
		Short:         "Get a value for a key with an optional @ db.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Example:       "  skate get foo@agent\n  skate get profile-pic@agent > profile-pic.jpg",
		Args:          cobra.ExactArgs(1),
		RunE:          get,
	}

	deleteCmd = &cobra.Command{
		Use:     "delete KEY[@DB]",
		Short:   "Delete a key with an optional @ db.",
		Aliases: []string{"del", "rm"},
		Example: "  skate delete foo@agent",
		Args:    cobra.ExactArgs(1),
		RunE:    del,
	}

	listCmd = &cobra.Command{
		Use:     "list [@DB]",
		Short:   "List key value pairs with an optional @ db.",
		Aliases: []string{"ls"},
		Example: "  skate list @agent\n  skate list @agent --keys-only\n  skate list @agent --delimiter \"=\"",
		Args:    cobra.MaximumNArgs(1),
		RunE:    list,
	}

	listDbsCmd = &cobra.Command{
		Use:     "list-dbs",
		Short:   "List databases.",
		Aliases: []string{"ls-db"},
		Example: "  skate list-dbs",
		Args:    cobra.NoArgs,
		RunE:    listDbs,
	}

	deleteDbCmd = &cobra.Command{
		Use:     "delete-db [@DB]",
		Hidden:  false,
		Short:   "Delete a database",
		Aliases: []string{"del-db", "rm-db"},
		Example: "  skate delete-db @agent --dry-run\n  skate delete-db @agent --yes",
		Args:    cobra.ExactArgs(1),
		RunE:    deleteDb,
	}

	unlockCmd = &cobra.Command{
		Use:     "unlock [@DB]",
		Short:   "Unlock an encrypted database for this OS session.",
		Example: "  printf '%s\\n' \"$SKATE_AGENT_PASSPHRASE\" | skate unlock @agent --init --passphrase-stdin\n  skate unlock @agent --passphrase-env SKATE_AGENT_PASSPHRASE\n  skate unlock @agent --session-ttl 8h",
		Args:    cobra.MaximumNArgs(1),
		RunE:    unlock,
	}

	lockCmd = &cobra.Command{
		Use:     "lock [@DB]",
		Short:   "Remove this session's unlock token for a database.",
		Example: "  skate lock @agent",
		Args:    cobra.MaximumNArgs(1),
		RunE:    lock,
	}

	statusCmd = &cobra.Command{
		Use:     "status [@DB]",
		Short:   "Show whether a database is encrypted and unlocked.",
		Example: "  skate status @agent",
		Args:    cobra.MaximumNArgs(1),
		RunE:    status,
	}

	encryptCmd = &cobra.Command{
		Use:     "encrypt [@DB]",
		Short:   "Encrypt an existing plaintext database.",
		Example: "  skate encrypt @default --dry-run\n  printf '%s\\n' \"$SKATE_AGENT_PASSPHRASE\" | skate encrypt @default --passphrase-stdin",
		Args:    cobra.MaximumNArgs(1),
		RunE:    encryptDB,
	}
)

type errDBNotFound struct {
	suggestions []string
}

func (err errDBNotFound) Error() string {
	if len(err.suggestions) == 0 {
		return "no suggestions found"
	}
	return fmt.Sprintf("did you mean %q", strings.Join(err.suggestions, ", "))
}

//nolint:wrapcheck
func set(cmd *cobra.Command, args []string) error {
	k, n, err := keyParser(args[0])
	if err != nil {
		return err
	}
	n = normalizeDBName(n)
	db, err := openKV(n)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	dataKey, err := dataKeyForDB(cmd, db, n)
	if err != nil {
		return err
	}
	if len(args) == 2 {
		encrypted, err := encryptValue(dataKey, k, []byte(args[1]))
		if err != nil {
			return err
		}
		return wrap(db, false, func(tx *badger.Txn) error {
			return tx.Set(k, encrypted)
		})
	}
	bts, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return err
	}
	encrypted, err := encryptValue(dataKey, k, bts)
	if err != nil {
		return err
	}
	return wrap(db, false, func(tx *badger.Txn) error {
		return tx.Set(k, encrypted)
	})
}

//nolint:wrapcheck
func get(cmd *cobra.Command, args []string) error {
	k, n, err := keyParser(args[0])
	if err != nil {
		return err
	}
	n = normalizeDBName(n)
	db, err := openKV(n)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	dataKey, err := dataKeyForDB(cmd, db, n)
	if err != nil {
		return err
	}
	var v []byte
	if err := wrap(db, true, func(tx *badger.Txn) error {
		item, err := tx.Get(k)
		if err != nil {
			return err
		}
		v, err = item.ValueCopy(nil)
		return err
	}); err != nil {
		return err
	}
	plaintext, err := decryptValue(dataKey, k, v)
	if err != nil {
		return err
	}
	printFromKV("%s", plaintext)
	return nil
}

func del(cmd *cobra.Command, args []string) error {
	k, n, err := keyParser(args[0])
	if err != nil {
		return err
	}
	n = normalizeDBName(n)
	db, err := openKV(n)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	if _, err := dataKeyForDB(cmd, db, n); err != nil {
		return err
	}

	return wrap(db, false, func(tx *badger.Txn) error {
		return tx.Delete(k)
	})
}

// TODO: use lists/tables/trees for this?
func listDbs(*cobra.Command, []string) error {
	dbs, err := getDbs()
	for _, db := range dbs {
		fmt.Println(db)
	}
	return err
}

// getDbs: returns a formatted list of available Skate DBs.
//
//nolint:wrapcheck
func getDbs() ([]string, error) {
	filepath, err := getFilePath()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath)
	if err != nil {
		return nil, err
	}
	var dbList []string
	for _, e := range entries {
		if e.IsDir() {
			dbList = append(dbList, e.Name())
		}
	}
	return formatDbs(dbList), nil
}

func formatDbs(dbs []string) []string {
	out := make([]string, 0, len(dbs))
	for _, db := range dbs {
		out = append(out, "@"+db)
	}
	return out
}

func unlock(cmd *cobra.Command, args []string) error {
	n, err := dbNameFromOptionalArg(args)
	if err != nil {
		return err
	}
	db, err := openKV(n)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	envelope, ok, err := readEnvelope(db)
	if err != nil {
		return err
	}
	if !ok {
		if !initEncryptedDB {
			return fmt.Errorf("database @%s is not encrypted; run `skate unlock @%s --init --passphrase-stdin` to initialize it", n, n)
		}
		values, err := plaintextValues(db)
		if err != nil {
			return err
		}
		if len(values) > 0 {
			return fmt.Errorf("database @%s has existing plaintext keys; run `skate encrypt @%s --passphrase-stdin` instead", n, n)
		}
	}
	passphrase, err := passphraseFromCommand(cmd)
	if err != nil {
		return err
	}
	var dataKey []byte
	initialized := false
	if ok {
		dataKey, err = unlockDataKey(envelope, passphrase)
		if err != nil {
			return err
		}
	} else {
		envelope, dataKey, err = initializeEncryptedDB(db, passphrase)
		if err != nil {
			return err
		}
		initialized = true
	}
	if err := saveSession(n, envelopeFingerprint(envelope), dataKey, sessionTTL); err != nil {
		return err
	}
	fmt.Printf("unlocked @%s\ninitialized: %t\nsession_ttl: %s\n", n, initialized, effectiveSessionTTL(sessionTTL))
	return nil
}

func initializeEncryptedDB(db *badger.DB, passphrase string) (keyEnvelope, []byte, error) {
	envelope, dataKey, err := newKeyEnvelope(passphrase)
	if err != nil {
		return keyEnvelope{}, nil, err
	}
	envelopeBts, err := marshalEnvelope(envelope)
	if err != nil {
		return keyEnvelope{}, nil, err
	}
	if err := wrap(db, false, func(tx *badger.Txn) error {
		if err := tx.Set([]byte(envelopeKey), envelopeBts); err != nil {
			return fmt.Errorf("write key envelope: %w", err)
		}
		return nil
	}); err != nil {
		return keyEnvelope{}, nil, err
	}
	return envelope, dataKey, nil
}

func lock(_ *cobra.Command, args []string) error {
	n, err := dbNameFromOptionalArg(args)
	if err != nil {
		return err
	}
	if err := removeSession(n); err != nil {
		return err
	}
	fmt.Printf("locked @%s\n", n)
	return nil
}

func status(_ *cobra.Command, args []string) error {
	n, err := dbNameFromOptionalArg(args)
	if err != nil {
		return err
	}
	db, err := openKV(n)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	envelope, encrypted, err := readEnvelope(db)
	if err != nil {
		return err
	}
	fp := ""
	if encrypted {
		fp = envelopeFingerprint(envelope)
	}
	fmt.Printf("database: @%s\nencrypted: %t\nsession: %s\n", n, encrypted, sessionStatus(n, fp))
	return nil
}

func encryptDB(cmd *cobra.Command, args []string) error {
	n, err := dbNameFromOptionalArg(args)
	if err != nil {
		return err
	}
	db, err := openKV(n)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	if _, ok, err := readEnvelope(db); err != nil || ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("database @%s is already encrypted", n)
	}
	values, err := plaintextValues(db)
	if err != nil {
		return err
	}
	if dryRun {
		fmt.Printf("database: @%s\nkeys_to_encrypt: %d\n", n, len(values))
		return nil
	}
	passphrase, err := passphraseFromCommand(cmd)
	if err != nil {
		return err
	}
	envelope, dataKey, err := newKeyEnvelope(passphrase)
	if err != nil {
		return err
	}
	envelopeBts, err := marshalEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := wrap(db, false, func(tx *badger.Txn) error {
		if err := tx.Set([]byte(envelopeKey), envelopeBts); err != nil {
			return fmt.Errorf("write key envelope: %w", err)
		}
		for key, value := range values {
			encrypted, err := encryptValue(dataKey, []byte(key), value)
			if err != nil {
				return err
			}
			if err := tx.Set([]byte(key), encrypted); err != nil {
				return fmt.Errorf("write encrypted value: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := saveSession(n, envelopeFingerprint(envelope), dataKey, sessionTTL); err != nil {
		return err
	}
	fmt.Printf("encrypted @%s\nkeys_encrypted: %d\nsession_ttl: %s\n", n, len(values), effectiveSessionTTL(sessionTTL))
	return nil
}

// getFilePath: get the file path to the skate databases.
//
//nolint:wrapcheck
func getFilePath(args ...string) (string, error) {
	var dd string
	if dir := os.Getenv("SKATE_DATA_DIR"); dir != "" {
		dd = dir
	} else {
		scope := gap.NewScope(gap.User, "charm")
		dataPath, pathErr := scope.DataPath("")
		if pathErr != nil {
			return "", pathErr
		}
		dd = filepath.Join(dataPath, "kv")
	}
	if err := os.MkdirAll(dd, 0o750); err != nil {
		return "", err
	}
	return filepath.Join(append([]string{dd}, args...)...), nil
}

// deleteDb: delete a Skate database.
//
//nolint:wrapcheck
func deleteDb(_ *cobra.Command, args []string) error {
	path, err := findDb(args[0])
	var errNotFound errDBNotFound
	if errors.As(err, &errNotFound) {
		fmt.Fprintf(os.Stderr, "%q does not exist, %s\n", args[0], err.Error())
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "unexpected error: %s", err.Error())
		os.Exit(1)
	}
	var confirmation string

	home, err := os.UserHomeDir()
	showpath := path
	if err == nil && strings.HasPrefix(path, home) {
		showpath = filepath.Join("~", strings.TrimPrefix(showpath, home))
	}
	message := fmt.Sprintf("Are you sure you want to delete '%s' and all its contents? (y/n)", warningStyle.Render(showpath))
	message = lipgloss.NewStyle().Width(78).Render(message)
	if dryRun {
		fmt.Fprintf(os.Stderr, "Would delete %q\n", showpath)
		return nil
	}
	if assumeYes {
		if err := finishDeleteDb(path, showpath, args[0]); err != nil {
			return err
		}
		return nil
	}
	fmt.Println(message)

	// TODO: use huh
	if _, err := fmt.Scanln(&confirmation); err != nil {
		return err
	}
	if confirmation == "y" {
		if err := finishDeleteDb(path, showpath, args[0]); err != nil {
			return err
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "Did not delete %q\n", showpath)
	return nil
}

func finishDeleteDb(path, showpath, dbArg string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("delete database: %w", err)
	}
	if n, err := dbNameFromOptionalArg([]string{dbArg}); err == nil {
		_ = removeSession(n)
	}
	fmt.Fprintf(os.Stderr, "Deleted %q\n", showpath)
	return nil
}

// findDb: returns the path to the named db or an errDBNotFound if no
// match is found.
func findDb(name string) (string, error) {
	sName, err := nameFromArgs([]string{name})
	if err != nil {
		return "", err
	}
	path, err := getFilePath(sName)
	if err != nil {
		return "", err
	}
	_, err = os.Stat(path)
	if sName == "" || os.IsNotExist(err) {
		dbs, err := getDbs()
		if err != nil {
			return "", err
		}
		var suggestions []string
		for _, db := range dbs {
			diff := int(math.Abs(float64(len(db) - len(name))))
			levenshteinDistance := levenshtein.ComputeDistance(name, db)
			suggestByLevenshtein := levenshteinDistance <= diff
			if suggestByLevenshtein {
				suggestions = append(suggestions, db)
			}
		}
		return "", errDBNotFound{suggestions: suggestions}
	}
	return path, nil
}

//nolint:wrapcheck
func list(cmd *cobra.Command, args []string) error {
	var k string
	var pf string
	if keysIterate || valuesIterate {
		pf = "%s\n"
	} else {
		var err error
		pf, err = strconv.Unquote(fmt.Sprintf(`"%%s%s%%s\n"`, delimiterIterate))
		if err != nil {
			return err
		}
	}
	if len(args) == 1 {
		k = args[0]
	}
	_, n, err := keyParser(k)
	if err != nil {
		return err
	}
	n = normalizeDBName(n)
	db, err := openKV(n)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	dataKey, err := dataKeyForDB(cmd, db, n)
	if err != nil {
		return err
	}
	err = db.Sync()
	if err != nil {
		return err
	}
	return db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		opts.Reverse = reverseIterate
		if keysIterate {
			opts.PrefetchValues = false
		}
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			if isInternalKey(k) {
				continue
			}
			if keysIterate {
				printFromKV(pf, k)
				continue
			}
			err := item.Value(func(v []byte) error {
				plaintext, err := decryptValue(dataKey, k, v)
				if err != nil {
					return err
				}
				if valuesIterate {
					printFromKV(pf, plaintext)
				} else {
					printFromKV(pf, k, plaintext)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func nameFromArgs(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	_, n, err := keyParser(args[0])
	if err != nil {
		return "", err
	}
	return n, nil
}

func dbNameFromOptionalArg(args []string) (string, error) {
	n, err := nameFromArgs(args)
	if err != nil {
		return "", err
	}
	return normalizeDBName(n), nil
}

func normalizeDBName(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

func dataKeyForDB(_ *cobra.Command, db *badger.DB, dbName string) ([]byte, error) {
	envelope, ok, err := readEnvelope(db)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("database @%s is not encrypted; run `skate unlock @%s --init --passphrase-stdin` for a new database or `skate encrypt @%s --passphrase-stdin` for an existing plaintext database", dbName, dbName, dbName)
	}
	fp := envelopeFingerprint(envelope)
	dataKey, err := loadSession(dbName, fp)
	if err == nil {
		return dataKey, nil
	}
	var passphrase string
	if passphraseEnv != "" {
		passphrase = os.Getenv(passphraseEnv)
	}
	if passphrase == "" {
		passphrase = os.Getenv("SKATE_PASSPHRASE")
	}
	if passphrase == "" {
		return nil, err
	}
	dataKey, err = unlockDataKey(envelope, passphrase)
	if err != nil {
		return nil, err
	}
	if err := saveSession(dbName, fp, dataKey, sessionTTL); err != nil {
		return nil, err
	}
	return dataKey, nil
}

func readEnvelope(db *badger.DB) (keyEnvelope, bool, error) {
	var envelopeBts []byte
	err := wrap(db, true, func(tx *badger.Txn) error {
		item, err := tx.Get([]byte(envelopeKey))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return errEncryptedDBNotInitialized
		}
		if err != nil {
			return fmt.Errorf("read key envelope: %w", err)
		}
		envelopeBts, err = item.ValueCopy(nil)
		if err != nil {
			return fmt.Errorf("copy key envelope: %w", err)
		}
		return nil
	})
	if errors.Is(err, errEncryptedDBNotInitialized) {
		return keyEnvelope{}, false, nil
	}
	if err != nil {
		return keyEnvelope{}, false, err
	}
	envelope, err := unmarshalEnvelope(envelopeBts)
	if err != nil {
		return keyEnvelope{}, false, err
	}
	return envelope, true, nil
}

func plaintextValues(db *badger.DB) (map[string][]byte, error) {
	values := make(map[string][]byte)
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			if isInternalKey(key) {
				continue
			}
			value, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("copy plaintext value: %w", err)
			}
			values[string(key)] = value
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read plaintext values: %w", err)
	}
	return values, nil
}

func isInternalKey(key []byte) bool {
	return string(key) == envelopeKey
}

func passphraseFromCommand(cmd *cobra.Command) (string, error) {
	if passphraseEnv != "" {
		passphrase := os.Getenv(passphraseEnv)
		if passphrase == "" {
			return "", fmt.Errorf("environment variable %s is empty; set it or use --passphrase-stdin", passphraseEnv)
		}
		return passphrase, nil
	}
	if passphrase := os.Getenv("SKATE_PASSPHRASE"); passphrase != "" {
		return passphrase, nil
	}
	if passphraseStdin {
		passphrase, err := readSecret(cmd.InOrStdin())
		if err != nil {
			return "", err
		}
		if passphrase == "" {
			return "", fmt.Errorf("empty passphrase; provide one with `printf 'secret\\n' | skate unlock @default --passphrase-stdin`")
		}
		return passphrase, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no passphrase provided; use --passphrase-stdin, --passphrase-env NAME, or SKATE_PASSPHRASE")
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	bts, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	passphrase := strings.TrimRight(string(bts), "\r\n")
	if passphrase == "" {
		return "", fmt.Errorf("empty passphrase")
	}
	return passphrase, nil
}

func effectiveSessionTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return defaultSessionTTL
	}
	return ttl
}

func printFromKV(pf string, vs ...[]byte) {
	nb := "(omitted binary data)"
	fvs := make([]any, 0)
	isatty := term.IsTerminal(int(os.Stdout.Fd()))
	for _, v := range vs {
		if isatty && !showBinary && !utf8.Valid(v) {
			fvs = append(fvs, nb)
		} else {
			fvs = append(fvs, string(v))
		}
	}
	fmt.Printf(pf, fvs...)
	if isatty && !strings.HasSuffix(pf, "\n") {
		fmt.Println()
	}
}

func keyParser(k string) ([]byte, string, error) {
	var key, db string
	ps := strings.Split(k, "@")
	switch len(ps) {
	case 1:
		key = strings.ToLower(ps[0])
	case 2:
		key = strings.ToLower(ps[0])
		db = strings.ToLower(ps[1])
	default:
		return nil, "", fmt.Errorf("bad key format, use KEY@DB")
	}
	return []byte(key), db, nil
}

func openKV(name string) (*badger.DB, error) {
	if name == "" {
		name = "default"
	}
	path, err := getFilePath(name)
	if err != nil {
		return nil, err
	}
	return badger.Open(badger.DefaultOptions(path).WithLoggingLevel(badger.ERROR)) //nolint:wrapcheck
}

func init() {
	rootCmd.PersistentFlags().StringVar(&passphraseEnv, "passphrase-env", "", "environment variable containing the database passphrase")
	rootCmd.PersistentFlags().DurationVar(&sessionTTL, "session-ttl", defaultSessionTTL, "how long an unlock session remains valid")
	listCmd.Flags().BoolVarP(&reverseIterate, "reverse", "r", false, "list in reverse lexicographic order")
	listCmd.Flags().BoolVarP(&keysIterate, "keys-only", "k", false, "only print keys and don't fetch values from the db")
	listCmd.Flags().BoolVarP(&valuesIterate, "values-only", "v", false, "only print values")
	listCmd.Flags().StringVarP(&delimiterIterate, "delimiter", "d", "\t", "delimiter to separate keys and values")
	listCmd.Flags().BoolVarP(&showBinary, "show-binary", "b", false, "print binary values")
	getCmd.Flags().BoolVarP(&showBinary, "show-binary", "b", false, "print binary values")
	deleteDbCmd.Flags().BoolVar(&assumeYes, "yes", false, "delete without prompting")
	deleteDbCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be deleted")
	unlockCmd.Flags().BoolVar(&initEncryptedDB, "init", false, "initialize the encrypted database if needed")
	unlockCmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read the passphrase from stdin")
	encryptCmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read the passphrase from stdin")
	encryptCmd.Flags().BoolVar(&dryRun, "dry-run", false, "show how many keys would be encrypted")

	rootCmd.AddCommand(
		getCmd,
		setCmd,
		deleteCmd,
		listCmd,
		listDbsCmd,
		deleteDbCmd,
		unlockCmd,
		lockCmd,
		statusCmd,
		encryptCmd,
	)
}

func main() {
	if err := fang.Execute(context.Background(), rootCmd); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

func wrap(db *badger.DB, readonly bool, fn func(tx *badger.Txn) error) error {
	tx := db.NewTransaction(!readonly)
	if err := fn(tx); err != nil {
		tx.Discard()
		return err
	}
	return tx.Commit() //nolint:wrapcheck
}
