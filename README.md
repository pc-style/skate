# Skate

<p>
    <img src="https://stuff.charm.sh/skate/skate-header.png?2" width="480" alt="A nice rendering of a roller skate with the words ‘Charm Skate’ next to it"><br>
    <a href="https://github.com/charmbracelet/skate/releases"><img src="https://img.shields.io/github/release/charmbracelet/skate.svg" alt="Latest Release"></a>
    <a href="https://github.com/charmbracelet/skate/actions"><img src="https://github.com/charmbracelet/skate/workflows/build/badge.svg" alt="Build Status"></a>
</p>

A personal encrypted key-value store. 🛼

***
⚠️ As of v1.0.0 Skate operates locally and no longer syncs to the Charm Cloud. [Read more about why][sunset] and see [the v1.0.0 release notes](https://github.com/charmbracelet/skate/releases/tag/v1.0.0) for a migration guide. The Charm Cloud [sunsets][sunset] on 29 November 2024.

[sunset]: https://github.com/charmbracelet/charm?tab=readme-ov-file#sunsetting-charm-cloud
***

Skate is simple and powerful. Use it to save and retrieve anything you’d
like, including binary data. Values are encrypted at rest before they are
written to BadgerDB.

```bash
# Unlock or initialize an encrypted database once per session
printf '%s\n' "$SKATE_PASSPHRASE" | skate unlock @default --init --passphrase-stdin

# Store something
skate set kitty@default meow

# Fetch something
skate get kitty@default

# What’s in the store?
skate list @default

# Spaces are fine
skate set "kitty litter"@default "smells great"

# You can store binary data, too
skate set profile-pic@default < my-cute-pic.jpg
skate get profile-pic@default > here-it-is.jpg

# Unicode also works, of course
skate set 猫咪@default 喵
skate get 猫咪@default

# Lock the database when the session is done
skate lock @default

# For more info
skate --help

# Do creative things with skate list
skate set penelope@default marmalade
skate set christian@default tacos
skate set muesli@default muesli

skate list @default | xargs -n 2 printf '%s loves %s.\n'
```

## Installation

Use a package manager:

```bash
# macOS or Linux
brew tap charmbracelet/tap && brew install charmbracelet/tap/skate

# Arch Linux (btw)
pacman -S skate

# Nix
nix-env -iA nixpkgs.skate

# Debian/Ubuntu
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install skate

# Fedora/RHEL
echo '[charm]
name=Charm
baseurl=https://repo.charm.sh/yum/
enabled=1
gpgcheck=1
gpgkey=https://repo.charm.sh/yum/gpg.key' | sudo tee /etc/yum.repos.d/charm.repo
sudo yum install skate
```

Or download it:

- [Packages][releases] are available in Debian and RPM formats
- [Binaries][releases] are available for Linux, macOS, and Windows

Or just install it with `go`:

```bash
go install github.com/charmbracelet/skate@latest
```

[releases]: https://github.com/charmbracelet/skate/releases

## Other Features

### Encryption and sessions

Skate stores values encrypted with AES-GCM. Each database has a random data key.
That data key is wrapped by a passphrase-derived key and stored as metadata in
the database. The passphrase itself is never stored.

Unlock once per OS session:

```bash
printf '%s\n' "$SKATE_PASSPHRASE" | skate unlock @agent --init --passphrase-stdin --session-ttl 12h
```

After unlock, `set`, `get`, `list`, and `delete` use the session file until it
expires. Session files are written with `0600` permissions under
`$SKATE_SESSION_DIR`, `$XDG_RUNTIME_DIR/skate`, or `/tmp/skate-<uid>`.

Useful automation settings:

```bash
# Keep an agent's data separate from a human's local Skate data.
export SKATE_DATA_DIR="$HOME/.local/share/skate-agents"

# Keep unlock state in an explicit runtime directory.
export SKATE_SESSION_DIR="${XDG_RUNTIME_DIR:-/tmp}/skate-agent-session"

# Unlock without stdin when a secret manager injects an environment variable.
skate unlock @agent --passphrase-env SKATE_AGENT_PASSPHRASE
```

Encrypt an existing plaintext database:

```bash
skate encrypt @default --dry-run
printf '%s\n' "$SKATE_PASSPHRASE" | skate encrypt @default --passphrase-stdin
```

### List Filters

```bash
# list keys only
skate list @default -k

# list values only
skate list @default -v

# reverse lexicographic order
skate list @default -r

# add a custom delimeter between keys and values; default is a tab
skate list @default -d "\t"

# show binary values
skate list @default -b
```

### Databases

Sometimes you’ll want to separate your data into different databases:

```bash
# Database are automatically created on demand
printf '%s\n' "$SKATE_PASSPHRASE" | skate unlock @work-stuff --init --passphrase-stdin
skate set secret-boss-key@work-stuff password123

# Most commands accept a @db argument
skate set "office rumor"@work-stuff "penelope likes marmalade"
skate get "office rumor"@work-stuff
skate list @work-stuff

# Wait, what was that db named?
skate list-dbs
```

## Examples

Here are some of our favorite ways to use `skate`.

### Keep secrets out of your scripts

```bash
skate set gh_token@default GITHUB_TOKEN

#!/bin/bash
curl -su "$1:$(skate get gh_token@default)" \
    https://api.github.com/users/$1 \
    | jq -r '"\(.login) has \(.total_private_repos) private repos"'
```

### Keep passwords in their own database

```bash
skate set github@password.db PASSWORD
skate get github@password.db
```

### Use scripts to manage data

```bash
#!/bin/bash
skate set "$(date)@bookmarks.db" $1
skate list @bookmarks.db
```

What do you use `skate` for? [Let us know](mailto:vt100@charm.sh).

## Feedback

We’d love to hear your thoughts on this project. Feel free to drop us a note!

- [Twitter](https://twitter.com/charmcli)
- [The Fediverse](https://mastodon.social/@charmcli)
- [Discord](https://charm.sh/chat)

## License

[MIT](https://github.com/charmbracelet/skate/raw/main/LICENSE)

---

Part of [Charm](https://charm.sh).

<a href="https://charm.sh/"><img alt="The Charm logo" src="https://stuff.charm.sh/charm-badge.jpg" width="400"></a>

Charm热爱开源 • Charm loves open source
