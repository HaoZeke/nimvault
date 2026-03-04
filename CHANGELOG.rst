=========
Changelog
=========

.. towncrier release notes start

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
