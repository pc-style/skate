# AGENTS.md

## Cursor Cloud specific instructions

`skate` is a single-binary Go CLI: a personal key-value store backed by BadgerDB (see `README.md` and `main.go`). There is no server or web UI — everything runs through the `skate` command. Data is stored on disk under the user data path (`~/.local/share/charm/kv/<db>` on Linux), not in the repo.

### Toolchain
- Go is pinned to the version in `go.mod` (`go 1.24.2`); the system `go` resolves it automatically.
- `golangci-lint` v2 (config is `version: "2"` in `.golangci.yml`) is installed by the startup update script into `$(go env GOPATH)/bin` (i.e. `~/go/bin`). If `golangci-lint` is not found, add `~/go/bin` to `PATH` or run it via `$(go env GOPATH)/bin/golangci-lint`.

### Common commands
- Build: `go build -o skate .`
- Run: `./skate <cmd>` or `go run . <cmd>` (e.g. `./skate set kitty meow`, `./skate get kitty`, `./skate list`, `./skate list-dbs`).
- Lint: `golangci-lint run ./...` (CI in `.github/workflows/lint.yml` runs with `--issues-exit-code=0`, so lint findings never fail CI; locally it exits non-zero on findings).
- Test: `go test ./...` — note there are currently **no test files** in the repo, so this is a no-op.

### Gotchas
- `get`/`list`/`set` open the on-disk Badger db; output for some commands (e.g. `get`) has no trailing newline when not a TTY.
- Keys are lowercased; `KEY@DB` syntax selects/creates a database on demand. The default db is `default`.
