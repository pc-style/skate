# Skate for agents

Use Skate as an encrypted key-value store for one agent session.

## Setup

Pick one database name per agent or project.

```bash
export SKATE_DATA_DIR="$HOME/.local/share/skate-agents"
export SKATE_SESSION_DIR="${XDG_RUNTIME_DIR:-/tmp}/skate-agent-session"
export SKATE_DB="@agent"
```

Unlock once at the start of the session.

```bash
printf '%s\n' "$SKATE_AGENT_PASSPHRASE" | skate unlock "$SKATE_DB" --init --passphrase-stdin --session-ttl 12h
```

The passphrase is not stored in Skate settings. Skate stores an encrypted database key in Badger and a 0600 session file with the decrypted database key until the session TTL expires.

## Store values

Pass values as arguments for short strings.

```bash
skate set "github-token$SKATE_DB" "$GITHUB_TOKEN"
```

Pass larger or multiline values through stdin.

```bash
printf '%s' "$PRIVATE_NOTE" | skate set "private-note$SKATE_DB"
```

## Read values

```bash
skate get "github-token$SKATE_DB"
```

List keys without printing values.

```bash
skate list "$SKATE_DB" --keys-only
```

## End the session

```bash
skate lock "$SKATE_DB"
```

## Rules

- Use one explicit `@DB` per agent. Do not rely on the default database for shared machines.
- Unlock once per session. Do not put the passphrase in shell history.
- Prefer stdin for secret values.
- Use `SKATE_DATA_DIR` in tests and automation so agent data does not mix with a human's local Skate store.
- Treat the unlocked session file like a secret. It is scoped by filesystem permissions and expires, but same-user processes can still read files the OS allows them to read.
