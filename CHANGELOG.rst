=========
Changelog
=========

.. towncrier release notes start

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
