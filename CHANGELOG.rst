=========
Changelog
=========

.. towncrier release notes start

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
