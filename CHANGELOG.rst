=========
Changelog
=========

.. towncrier release notes start

nimvault 0.5.5 (2026-11-19)
===========================

Fixed
-----

- The Linux release binary no longer loads libpcre. Secret scanning and wrap globs are plain matchers, and the release workflow publishes static musl builds for amd64 and arm64 (`nimvault-linux-amd64`, `nimvault-linux-arm64`) alongside `nimvault-macos-arm64`. (linux-no-pcre)

nimvault 0.5.4 (2026-11-18)
===========================

Security
--------

- add refuses a symlink and a path containing a tab, newline or NUL, which the record format cannot store. (add-path-checks)
- `backend = age` with `signer = gpg` is refused when the config loads, and `seal`, `unseal` and `check` refuse it on a config built in code. gpg signs only what it encrypts, so that pair signed and verified nothing: changing one config line let an unsigned record, built from the public recipient alone, through a plain `unseal`. An unknown `backend` or `signer` value is refused too, instead of falling back to gpg or skipping the check under `--allow-unsigned`. (age-gpg-signer)
- A record or stub manifest is signed while it is still a temporary file, and the signature and the file are then renamed into place. A signing failure used to leave the new ciphertext under the old signature, or under none, so the vault no longer verified. (age-sign-before-rename)
- Age-backed record and manifest loads now verify and decrypt the same ciphertext
  bytes in memory. `unseal`, `get` and `check` no longer verify one on-disk read
  and decrypt another for ssh-signed age records. (age-verify-decrypt-one-read)
- `unseal --allow-unsigned` and `get --allow-unsigned` accept only a missing signature. A record or v5 blob with a good GPG signature from a key the config does not name is refused, as is an ssh-signed record whose detached signature does not verify against `allowed_signers`. Before, the flag turned off the signer check, so a record signed by any key in the keyring was written, though the CLI reference said such a signature stayed fatal. (allow-unsigned-signer)
- A record whose session-key packet names a key this machine holds and still fails to decrypt now fails `check` and `unseal`. gpg reports such a packet as `NO_SECKEY`, so one flipped byte made the record read as belonging to another wrap group, and `unseal` restored the rest of the vault without it. A record is skipped only when every `pkdecrypt_failed` code is 17 or the keyring holds none of the keys it names. `unseal` now prints how many records it could not open, and fails when it can open none instead of reporting an empty vault. (corrupt-session-key)
- `gc` shreds `.nimvault-<id>.tmp` plaintext that an interrupted `unseal` staged beside an entry, removes `<id>.gpg.tmp` and `<id>.gpg.pending.tmp` payloads a killed `add` or `seal` was writing, and keeps a pending blob whose record this machine cannot open instead of deleting another wrap group's ciphertext. (gc-leftovers)
- get decrypts a v6 payload in memory and does not write the plaintext under the runtime directory. (get-plaintext-memory)
- gitignore lines written for a vault path are anchored and escaped, so a leading hash or a glob character matches that path only. (gitignore-literal)
- gpg and age receive -- before the input path, so a path that looks like an option is not treated as one. (gpg-end-of-options)
- GPG signature checks bind to the configured keys. A record, stub manifest or blob verifies only when the primary key on its `VALIDSIG` line is the recipient or a wrap-rule recipient. A good signature from any other key in the keyring is refused by `unseal`, `get` and every command that loads records. (gpg-pin-signer)
- The pre-commit hook scans the index, and the pre-push hook scans the commits being pushed before check. (hooks-scan-index)
- The vault lock excludes other threads in the same process, and moving the lock does not close standard input. (inprocess-vault-lock)
- `lock` now enforces record signatures by default the same way `unseal` does.
  On a `signer = none` vault it refuses with "signature required" unless
  `--allow-unsigned` is passed; with that flag, present signatures still must
  verify. (lock-allow-unsigned)
- lock refuses to delete plaintext unless the blob matches the record, and shreds editor backups of an in-sync file. (lock-refuses-stale-blob)
- `lock` verifies record signatures with the configured signer, refuses a record path that fails the traversal check, and shreds editor backups only beside an entry that is present and matches its recorded hash. An unsigned record could name any `name~` file, including one outside `$HOME`, for shredding. (lock-verifies-records)
- A cross-filesystem `mv` keeps the source's mode. The copy fallback created the new file with the process umask, so a 0600 secret arrived 0644 and readable by other local users. (mv-copy-mode)
- A cross-filesystem `mv` overwrites the source before removing it, as `lock` does. It unlinked the source, which left the plaintext in its blocks and readable through any other link or open descriptor. (mv-shred-source)
- `mv` refuses a source reached through a directory symlink that leaves `$HOME` or the configured `root`. `rename` followed that symlink, so `mv` moved a file from outside the boundary to the new path. (mv-source-ancestors)
- Without a `root`, a record path containing a `..` component is refused, so `../../outside` and `/tmp/../etc/passwd` no longer pass the path check. (no-root-traversal)
- `check`, `status` and `get` take the vault lock. Each may rename a pending blob over the live one, and without the lock that rename could race a `seal` publishing the same blob. (promote-under-lock)
- A GPG recipient, in `.vault/config`, a `wrap` rule, `--recipient` or `NIMVAULT_GPG_RECIPIENT`, must be an email address, a key ID or a fingerprint; any other string is refused when the config loads. Such a spec went to gpg as a substring, so `recipient = Alice` made `Malice <malice@example.com>` an allowed signer and a record she signed was restored by a plain `unseal`. The signer lookup no longer matches a name at all. (recipient-names-refused)
- The data key in the signed per-entry record wins over an unsigned keys file, and seal writes that key back. (record-dek-wins)
- `rotate` now takes the vault lock before reading records, so a concurrent remove or move cannot be replayed by a stale force rewrite. (rotate-lock-order)
- The runtime directory is created mode 0700, tightened when it already exists, and refused when it is a symlink. (runtime-dir-owner)
- `scan --cached` and `scan --rev` no longer skip a staged or committed file whose name starts with `-` or contains a newline. The name reaches git as `<rev>:<name>` after `--`, so neither is an option. (scan-odd-names)
- `scan --cached` and `scan --rev` report a vaulted path in the index or in a commit, and match its bytes against the patterns, so a force-added vaulted file fails the pre-commit and pre-push hooks. Vaulted paths come from verified records and match by absolute path: an unsigned record no longer hides a file from the worktree walk, and a file in another repository that shares a stored relative name is not reported. (scan-reports-vaulted-plaintext)
- scan no longer skips every directory named tmp; that skip applies under .claude and .codex only. (scan-tmp-dir)
- seal writes new ciphertext to a pending blob and renames it over the live blob only after the record names it. (seal-keeps-old-blob)
- `seal` and `rotate --rekey` refuse to read plaintext whose path, or a directory symlink above it, resolves outside `$HOME` or the configured `root`. With an entry's directory swapped for such a symlink, `seal` encrypted the outside file into the blob and replaced the sealed copy. (seal-read-ancestors)
- With `--allow-unsigned`, split-vault commands now still verify a present combined-manifest stub signature and reject one from a non-configured signer. (split-stub-signature-check)
- `list` and `status` now verify record signatures before trusting record metadata, so they do not promote `.pending` blobs from unverified records. (status-list-verify-records)
- `unseal` opens each destination's parent by walking from `/` without following a symlink, then creates, writes, renames and shreds its staging file through that directory descriptor (`openat`/`renameat`/`unlinkat`). A parent swapped after the checks cannot redirect the plaintext. (unseal-dirfd-staging)
- With no `root`, `unseal` now re-walks each destination parent from the `$HOME`
  boundary path both before and after `renameat`. If the parent moved or now
  resolves outside the boundary after placement, the plaintext is overwritten
  through its descriptor and unlinked, and that entry fails. (unseal-home-boundary)
- `unseal` works on macOS, on Linux arm64, and on Linux without `/proc`. It handed gpg a `/proc/self/fd/<n>/` path to write, and opened directories with the x86-64 Linux values of `O_NOFOLLOW` and `O_DIRECTORY`; on arm64 those numbers are `O_LARGEFILE` and `O_DIRECT`, so the walk followed a directory symlink. The flags now come from `<fcntl.h>`. gpg and age write the plaintext to a pipe, and `unseal` copies it into a staging file it created with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600. CI runs the suite on Linux arm64 and macOS. (unseal-pipe-staging)
- unseal refuses a directory symlink above the destination that resolves outside `$HOME` or the configured `root`, and replaces a symlink at the destination instead of copying through it. (unseal-symlink-parents)
- `unseal`, `get` and `rotate` now take data keys from the same verified split
  record read that produced the entry list, instead of re-reading `.vault/e/*`
  records without signature checks. Blob integrity is rechecked on the bytes used
  for decrypt, and placement revalidates the live blob before writing plaintext. (verified-record-bytes)
- Path writes and plaintext shredding now reject ancestor symlink escapes from `$HOME` or a configured `root`, including `~/` spellings whose real path leaves that boundary. `mv` now refuses destination symlinks and uses a cross-filesystem fallback that cannot copy through them.

  Split-record loading now skips only genuine no-secret-key records; corrupt decryptable records fail `check` and `unseal` loudly. `check` reports how many records this machine could not open. `gc` also keeps `.pending` blobs named by in-flight `e/<id>.<ext>.tmp` records.

  GPG signer resolution is exact: email specs match the exact `<addr>`, key IDs/fingerprints match exactly, and signing selects an allowed signer explicitly with `--local-user`. `add`/`seal` now fail with a clear error when no allowed secret key is present. (round3-record-and-path-hardening)


Developer
---------

- The test workflow sets a git user name and email before the suite runs. Scratch repositories can commit, so the clone and hook tests see a history. (ci-git-identity)
- The `drain` comment says a child waiting to write to a full pipe never exits. (drain-comment)
- The `loadDeks` comments state that a key file also fills a record whose data-key field is empty, and that the records it reads are verified by its callers. (loaddeks-comment)
- Each audit test keyring lives in a short temp directory. gpg-agent puts its sockets there, and on macOS a name such as `nimvault_audit_<id>_unsignedstub` under the 49-byte temp dir made `S.gpg-agent.browser` longer than the 103-byte socket path limit, so the agent did not start and key generation failed. (macos-gpg-home)
- The test that `rotate` reads records under the vault lock now holds the lock from a separate Python process, runs the CLI `rotate` against it, removes a record while `rotate` waits, and checks both exit statuses and that the record stays removed. The forked child it used inherited the in-process lock gate in its held state, so it timed out after 30 s without running `rotate`, and its exit status was never checked. (rotate-lock-test)
- The test that `unseal` reports the records it could not open runs the CLI from inside the vault repository. Run from another git checkout, as in CI, the CLI refuses `root = repo` before it reaches the count. (unseal-count-test-cwd)


Changed
-------

- The `pre-push` hook passes `--remote` to `scan --rev`, so it scans only commits the remote's tracking refs do not reach. A new branch is no longer refused for a secret that is already in the remote's history. A remote commit this clone lacks gives an error that says to fetch, instead of a bare `git rev-list` failure. Hooks installed earlier keep their old script until reinstalled. (pre-push-new-commits)


Fixed
-----

- The README, threat model, headless GPG guide and `checkVault` docstring no longer call `check` keyless: it decrypts the records to read the blob digests. When no record opens, `check` says to import the secret key instead of suggesting a seal or a missing blob. (check-needs-record-key)
- check reads blob digests from the encrypted records. A public key alone cannot open those records, so it does not compare the blobs. (check-record-digests)
- A pre-v6 entry no longer vanishes when the vault moves to per-entry records. Its record ends in an empty data-key field, which the parser stripped and then rejected, so after an `add` the older entry left `list`, `unseal` and `check`, and `check` still called the vault consistent. A record that opens but holds no entry line is now counted: `check` reports it and fails, and `unseal` refuses to restore part of the vault. (empty-dek-record)
- ``nimvault hook`` refuses when ``core.hooksPath`` sends git to another hooks directory, since git would never run hooks written to ``.git/hooks``; ``nimvault doctor`` reports installed hooks that git no longer runs. Before this, a global hooks path left the pre-push ``nimvault check`` inert, and a blob replaced without its record reached the remote unchecked. (hooks-under-hookspath)
- With `root = repo`, the CLI compared the vault repository with git's top level as strings. git prints the top level with symlinks resolved, so a vault named through a symlinked path, as anything under the macOS temp dir is, was refused as living in another repository. The two are now compared as directories. (root-repo-resolved-path)
- Config load now refuses 8-hex short GPG key IDs and asks for a 16-hex key ID or a full fingerprint. (short-gpg-key-id)
- add and seal leave an unchanged per-entry record on disk. Two machines that each add a different file no longer rewrite a shared stem, so git can merge them. (split-record-stable)
- A missing `allowed_signers`, `signer_identity` or `ssh-keygen` now fails `unseal`, `get` and `check` with the reason. A record whose signature could not be checked for one of those reasons was skipped and not counted, so `unseal` printed "vault is empty" and exited 0, and `check` asked for a secret key. (ssh-signer-settings)
- A recipient that names an encryption subkey, by ID or fingerprint and with or without gpg's trailing `!`, works again. The signer lookup matched only primary keys, so such a vault could not find a key to sign with, and a record signed by the vault's own key was refused as signed by an unconfigured one. (subkey-recipient)
- A `$HOME` or vault root reached through a symlink no longer refuses every path under it. The path checks resolved the path but compared it with the base as spelled, so `add` refused each file with "outside the vault root", a vault opened through a symlinked `--vault` path with `root = repo` failed the same way, and `unseal` refused entries under a directory symlink that stays inside `$HOME`. The base is now resolved too. (symlinked-base)
- `unseal` restores a vault larger than the open-file limit. It kept one directory descriptor per entry open for the whole run, so 80 entries failed under `ulimit -n 64`. Each entry is now staged, decrypted, checked and renamed into place before the next is staged, direct gpg blobs eight at a time. In-band gpg signatures are all checked first by a decryption whose output is discarded, so no plaintext is written before every signature has passed. Any failure shreds each staging file not yet placed, through its own descriptor. A direct (v5) entry is staged once instead of twice. (unseal-entry-at-a-time)


Miscellaneous
-------------

- The `check` reference no longer opens with "Verify every blob". It verifies the blob of each record this machine can open, and counts the records it could not. (check-scope-doc)
- The threat model and the configuration reference now say that `.vault/config` is plaintext, committed and unsigned, and that it names who may sign records and who the next `seal` encrypts to, so a change to it is a change to the trust root and should be reviewed like code. They also spell out that a key named only in a `wrap` rule can sign a record for any path, such as `~/.bashrc`, and every machine that unseals writes it. (config-trust)
- The manifest reference no longer calls every data key hex. A gpg data key is 64 hex digits; an age data key is an `AGE-SECRET-KEY-1...` identity. (dek-field-doc)
- The threat model now states explicitly that `lock` and cross-device `mv`
  overwrite the source inode before unlinking it, so other hard links to that
  inode lose the plaintext too. (hardlink-shred-note)
- The cross-process vault lock test waits on a pipe handshake instead of a fixed sleep, so a slow child cannot lose the race. (lock-test-handshake)
- The threat model lists the commands that still check a path and then use it by name: `mv` creates, renames and copies by name, `lock` and `gc` overwrite and unlink by name, and `seal` reads by name. The CLI reference no longer says every record signature is checked during decryption; that holds for gpg, while an ssh signer's detached signature is checked before the record is decrypted. (residual-race-docs)
- The unseal reference and threat model describe where `unseal` stages plaintext, why it stages beside the destination, and that `gc` shreds what a killed run leaves. (unseal-staging)
- The docs now consistently say that `check` verifies blobs for records this identity can open, and reports how many records it could not open. (check-scope-round5)


nimvault 0.5.3 (2026-09-13)
===========================

Security
--------

- Payload encrypt writes a sibling tmp file and renames. unseal holds the
  vault lock and decrypts into the owner-only work dir, not dest.nimvault-tmp.
  add stores an absolute path and refuses one outside the vault root. (atomic-blob)
- `init` rejects a recipient that contains a newline. Duplicate singleton
  keys in `.vault/config` are fatal instead of last-wins. (config-single-line)
- GPG status checks match `[GNUPG:]` fields, not substrings. Encrypt uses
  `--no-options --no-encrypt-to`. BADSIG is inspected before a nonzero exit. (gpg-status-tokens)
- `scan` reports path, rule, line and byte size. It does not print the
  matching line. (scan-metadata-only)
- A wrap-subset machine no longer deletes unread `.vault/e/` records or
  foreign `keys.*` files. `seal` refuses to treat an unread vault as empty. (unread-split-keep)
- `add`, `seal`, `rm`, `mv`, `rotate` and `check` verify split-record
  signatures. `check` fails when this identity cannot open any record. (verify-on-mutate)


Fixed
-----

- `.gitignore` lines are repo-relative and passed to git after `--`. (gitignore-relative)
- `rotate` rewraps per-entry records as well as `keys.*`. The seal key
  includes wrap rules, so a wrap edit is not a silent no-op seal. (rotate-rewrapping)
- Wrap patterns are globs. `?|+()` are literals. A `~/` rule matches a
  `root = repo` stored path. (wrap-glob-literal)


nimvault 0.5.2 (2026-09-12)
===========================

Security
--------

- A per-entry record with a bad or missing signature is refused. A record
  this identity cannot decrypt is still skipped. (split-record-sig)


nimvault 0.5.1 (2026-09-12)
===========================

Security
--------

- `add-dir` refuses file and directory symlinks so a planted link cannot
  pull a file from outside the named tree into the vault. (add-dir-symlinks)
- The documentation workflow builds pull requests with `contents: read` and
  deploys only from a push-gated job that holds write. (docs-ci-read)
- Plaintext manifests, data keys and `get` scratch files are written in an
  owner-only work directory, never as `.vault/.plain` or a predictable name
  under `/tmp`. (work-dir-plaintext)


Added
-----

- `nimvault init` writes `.vault/config`. `nimvault hook` installs a
  pre-push `check` hook and a pre-commit `scan` hook. (init-hook)
- `nimvault lock` removes in-sync plaintext and refuses if any file is
  modified. `unseal` brings the files back. (lock)
- Each entry is now its own signed encrypted record under `.vault/e/`, so
  two machines that add different files no longer fight over one
  `manifest.gpg`. (split-trust-root)
- `nimvault who` prints which wrap-rule recipients can open each entry. (who)


Changed
-------

- Docs match the live CLI: version string, age/GPG backends, wrap/signer
  config keys, selective unseal, threat model, and headless GPG. (docs-accuracy)


Fixed
-----

- `nimvault check` fails when a v6 vault has matching blobs but no data-key
  file, so CI cannot pass a vault that will not unseal. (check-missing-keys)
- `add`, `rm`, `mv` and `add-dir` keep the recorded seal key, so the next
  seal still skips unchanged files instead of re-encrypting the whole vault. (keep-seal-key)
- `add` and `add-dir` write v6 data keys immediately, so a new entry in a
  sealed vault can be rewrapped by `rotate` without a forced reseal. (add-v6-deks)


nimvault 0.5.0 (2026-08-14)
===========================

Added
-----

- `nimvault check` verifies every blob against the hash the manifest records for
  it, without decrypting anything or needing key material, and exits non-zero when
  anything is inconsistent — so a pre-push hook or a continuous-integration job
  can gate on it.

  `status` answers a different question: it compares the *plaintext* on this
  machine against the manifest's `contentHash`, so it says nothing about whether
  the blobs still match. A blob committed without the manifest that vouches for it
  therefore looks healthy in `status` right up until an `unseal` on another
  machine, where the plaintext is gone and the failure is unrecoverable rather
  than inconvenient. `check` closes that gap; the two commands are complementary
  and neither replaces the other.

  The manifest is a signed list of per-blob digests, which is a one-level Merkle
  construction (Merkle, CRYPTO 1987, `doi:10.1007/3-540-48184-2_32`): checking
  each leaf against it detects a drifted blob and needs no key. (check)
- Payloads are now encrypted under a per-file data key, and the data keys live in
  one small file encrypted to the recipients (format v6).

  Until now each blob was encrypted straight to the recipient. Both backends do
  envelope encryption internally — GPG draws a session key per file, age a file
  key — but that wrapping lives *inside* the blob, so the recipient was baked into
  every payload and changing or adding one rewrote the whole vault. On a
  158-entry vault, letting a second machine read meant a full re-encrypt and a
  diff nobody could review.

  `nimvault rotate` rewraps the data keys to whoever `.vault/config` now names and
  leaves every payload untouched, so adding a machine costs one small file.
  `nimvault rotate --rekey` re-encrypts every payload under a fresh data key
  instead.

  The two are deliberately separate. Rewrapping rotates the *wrapping* key: a
  recipient that should no longer open the vault stops being able to. It does
  nothing about a data key that has already leaked, because the old ciphertext is
  unchanged and the old key still opens it — only `--rekey` answers that. The
  distinction between cheap rewrapping and real re-encryption is the subject of
  Everspaugh et al., CRYPTO 2017 (`doi:10.1007/978-3-319-63697-9_4`); updatable
  encryption exists to narrow the gap (Lehmann and Tackmann, EUROCRYPT 2018,
  `doi:10.1007/978-3-319-78372-7_22`).

  Migration is incremental and needs no action: a v5 entry moves to v6 when its
  plaintext next changes, so ordinary work drains the old format. Mixed vaults
  read correctly — an entry with a data key is v6, one without is v5, and the key
  file is the discriminator. `nimvault seal --force` migrates everything at once.

  Data keys are distinct per entry, so a leak of one opens one, and a key whose
  entry has been removed is dropped rather than kept. (envelope-keys)
- `nimvault gc` removes blobs in `.vault/` that no manifest entry points at, with
  `--dry-run` to list them first.

  Orphans are reachable when a mutation is interrupted between writing a blob and
  writing the manifest that names it — the vault lock makes that rarer but does
  not remove the case. An orphan is not only clutter: it is a readable copy of a
  secret that nothing tracks, so nothing will ever rotate or remove it.

  The manifest, the data-key files, and every blob a live entry names are left
  alone. (gc)
- `nimvault get <path>` prints one entry's plaintext on stdout without unsealing
  the vault or writing anything to disk. It performs the same path-safety and
  blob-integrity checks `unseal` does, so a caller reading a single credential
  gets the same guarantees as one restoring everything. (get)
- `wrap` rules in `.vault/config` decide which recipients may open which entries,
  so not every machine has to be able to read every secret:

  ```ini
  recipient = LAPTOPKEY
  wrap = ~/.ssh/**:LAPTOPKEY
  wrap = **:LAPTOPKEY,BUILDBOXKEY
  ```

  The first matching rule wins, so order is precedence. An entry matching no rule
  uses `recipient`, which is why a config without `wrap` lines behaves exactly as
  before.

  Data keys are grouped by recipient set and each group is written to its own
  `.vault/keys.<group>.gpg`, encrypted to that group alone. A machine decrypts
  the group files its key opens and no others. `unseal` restores what it can
  read; `check` needs no key at all, so integrity is verifiable from anywhere.
  `rotate` recomputes groups, so editing the rules and rotating moves an entry's
  key between group files without touching any payload.

  Key files are encrypted but not signed. gpg exits non-zero when it cannot
  *verify* a signature even after decrypting the content perfectly well, so a
  signed key file would be unreadable on any machine that did not also hold the
  signer's public key — requiring every machine to import every other machine's
  key just to read. That coupling buys nothing here: the manifest remains the
  trust root, it is signed, and it records the digest of every blob, so a tampered
  key file causes a decryption failure rather than a forged plaintext.

  Groups are only worth something when machines hold *different* keys. Sharing one
  private key across machines means every machine opens every group and the split
  is decoration. (per-path-recipients)
- The vault no longer has to live in the repository you are standing in. Every
  command accepts `--vault DIR`, and the location also resolves from
  `NIMVAULT_VAULT_REPO` or a `.nimvault` pointer file committed in the content
  repository.

  This exists so `.vault/` can sit in a *private* repository while the dotfiles it
  protects stay public. A vault inside a public repo archives its ciphertext
  permanently — anyone who clones or forks keeps a copy, and on GitHub the objects
  remain fetchable through the fork network even after a history rewrite. Neither
  key rotation nor `rotate --rekey` reaches that, because both act on the working
  tree. Separating the repositories is worth more than any feature here.

  Reading is unaffected: the manifest already stores target paths with a `~/`
  prefix, so entries do not care which repository their blobs came from.

  `root` is refused rather than guessed when it is set and the vault lives
  elsewhere, since "relative to the repository" stops being a single answer once
  there are two.

  `scan` previously advertised a `--vault` flag that was parsed and then ignored;
  it now does what it says. (private-vault-repo)
- `nimvault unseal` now accepts paths, restoring only the entries named instead
  of the whole vault. A directory restores everything beneath it, and a selector
  matching nothing raises rather than reporting success for zero work. Bare
  `unseal` is unchanged. (selective-unseal)
- New how-to on service vaults: giving an unattended machine only the secrets it
  needs, encrypted to a key that needs no passphrase, without widening the
  personal vault. (service-vault-howto)


Changed
-------

- `nimvault seal` now re-encrypts only the files whose plaintext changed. GPG and
  age both draw a fresh session key per run, so re-sealing an untouched file still
  produced a different blob: a one-file edit arrived in git as a diff touching
  every blob in the vault, and the real change was invisible inside it. A file is
  skipped when its plaintext hash, its blob and that blob's own hash all still
  agree with the manifest, so a deleted or corrupted blob is still rebuilt.

  The manifest (v5) records a seal key covering the backend, recipient, identity
  and signer. Changing any of them re-encrypts everything, because unchanged
  plaintext still owes a fresh blob under a new key; a v4 manifest with no
  recorded key also seals in full once to establish one. `nimvault seal --force`
  re-encrypts regardless. (incremental-seal)
- A `seal` that changes nothing no longer rewrites the manifest. The manifest is
  encrypted and signed, so writing it is itself a change: without this, every
  seal left one modified file and a fresh signature over identical content, and
  the incremental seal above could never produce a clean `git status`.

  Mutating commands (`seal`, `add`, `add-dir`, `rm`, `mv`) now take a per-vault
  lock before touching the manifest. Each of them rewrites the manifest from a
  copy read moments earlier, so two at once was a lost update: both read the same
  entries, both wrote, and the loser's blob stayed on disk with no entry pointing
  at it. The lock is an `fcntl` record under `$XDG_RUNTIME_DIR`, so the kernel
  releases it even on a crash, a vault checkout gains no untracked file, and a
  read-only checkout can still be locked. It excludes other nimvault processes,
  not threads within one.

  The manifest is now encrypted to a temporary file and renamed into place, so a
  concurrent reader sees either the old manifest or the new one, never a
  half-written trust root. (seal-noop-and-lock)


Fixed
-----

- Emptying a vault now drops its data keys. `seal` returned early when the
  manifest held no entries, before the pruning that removes key files for
  entries that no longer exist — leaving a key able to open blobs while
  guarding nothing, which is the case that pruning exists to prevent. (empty-vault-keys)
- The manifest and the blobs it vouches for are now flushed to stable storage in
  the order that survives a crash. Renaming the manifest into place is atomic
  against a concurrent reader, which is a different property from durability: the
  rename can reach disk before the bytes it points at, leaving the trust root for
  every blob present and empty. The orderings file systems actually guarantee
  here are narrower than the write-temp-then-rename idiom suggests (Bornholt et
  al., ASPLOS 2016, `doi:10.1145/2872362.2872406`; Chidambaram et al., SOSP 2013,
  `doi:10.1145/2517349.2522726`).

  `seal` now flushes each new blob before writing the manifest that records its
  hash, so a crash cannot leave an entry promising bytes that never landed — which
  would have surfaced later as an integrity failure on a file nobody touched. (manifest-durability)


nimvault 0.5.0 (2026-08-14)
===========================

No significant changes.


nimvault 0.4.1 (2026-06-26)
===========================

Changed
-------

- ``status`` uses manifest **v4** plaintext ``contentHash`` when present (no GPG per entry).
- In-process SHA-256 via ``checksums`` instead of spawning ``sha256sum``.
- Default GPG batch parallelism raised to 8 (``NIMVAULT_GPG_PARALLEL``).


nimvault 0.4.0 (2026-03-12)
===========================

Added
-----

- New ``add-dir`` command to recursively add directories to the vault. Each file in a directory tree is encrypted individually with its own blob ID, and the directory structure is preserved via relative paths in the manifest. (#12)
- Manifest v3 format with ``EntryKind`` field to distinguish files from directories. Backward compatible with v1 and v2 manifests. (#13)


nimvault 0.3.0 (2026-03-11)
===========================

Added
-----

- ``pixi run install`` task builds in release mode and installs to ``~/.local/bin/nimvault``. (pixi-install)


Fixed
-----

- ``seal`` and ``unseal`` now process GPG operations in batches of 4 instead of launching all processes simultaneously, preventing "Cannot allocate memory" failures on systems with many vault entries and high memory pressure. (batch-gpg)


nimvault 0.2.0 (2026-03-04)
===========================

Security
--------

- ``unseal`` now decrypts to temporary files and verifies all signatures before moving any file to its final path. This prevents release of unverified plaintext, where GPG streams decrypted content to disk before the signature check completes. (atomic-unseal)
- Manifest v2 stores SHA-256 hashes of encrypted blobs. ``unseal`` verifies each blob hash before decryption, preventing ciphertext forgery and swap attacks. (blob-hashes)
- All vault blobs and the manifest are now GPG-signed during ``seal``. On ``unseal``, signature verification detects tampered or forged blobs (warns for unsigned legacy vaults). (blob-signing)
- All GPG invocations now use direct process execution instead of shell interpolation, eliminating command injection via malicious ``.vault/config`` recipient values. (cmd-injection)
- Missing signatures and blob hashes are now fatal by default on ``unseal``, preventing downgrade attacks where an attacker replaces v2 manifests with unsigned v1 payloads. Pass ``--allow-unsigned`` to explicitly accept legacy unsigned vaults. (downgrade-attack)
- ``nimvault add`` now refuses files already tracked by git, preventing accidental plaintext commits alongside encrypted vault blobs. (git-tracked)
- ``unseal`` now validates that resolved paths stay within expected boundaries (repo root or ``$HOME``), preventing directory traversal via crafted manifest entries. (path-traversal)


Added
-----

- ``nimvault add`` now automatically appends the stored path to ``.gitignore`` when the file is not already ignored, preventing accidental plaintext commits. (auto-gitignore)
- ``--no-gitignore`` flag for ``nimvault add`` to opt out of automatic ``.gitignore`` updates and get a warning instead. (no-gitignore-flag)


nimvault 0.1.0 (2026-03-02)
===========================

Added
-----

- GPG-encrypted opaque-blob vault with randomized filenames and encrypted manifest.
- 3-tier recipient resolution: CLI flag, environment variable, ``.vault/config`` file.
- Parallel GPG encryption and decryption via ``startProcess``.
- 7 subcommands: ``seal``, ``unseal``, ``add``, ``rm``, ``mv``, ``list``, ``status``.
- Root-relative path mode (``root = repo`` in config) for repo-scoped vaults.
- ``resolvePath`` and ``storePath`` for transparent path mode abstraction.
- Positional argument support via cligen (``nimvault add <path>``).
- SHA-256 sync status checking (``nimvault status``).
- Sphinx + Shibuya documentation with Graphviz DOT diagrams.
- Nim API docs via ``nim doc --project``.
- GitHub Actions CI: test matrix (Nim 2.0 + 2.2), docs build, linting, tag-triggered releases.
- Keybase GPG key management howto.
- chezmoi integration howto with run_before auto-unseal.

Developer
---------

- cligen ``dispatchMulti`` with ``do``-prefixed wrappers to avoid symbol collisions.
- Test suite: manifest unit tests, GPG encrypt/decrypt cycle, full integration workflow, root-relative mode tests.
- Throwaway GPG key generation in tests with restricted GNUPGHOME permissions.
