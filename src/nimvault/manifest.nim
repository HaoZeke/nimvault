## Vault manifest operations: entry types, load/save, ID generation.

import std/[os, strutils, strformat, sysrand]
import ./gpg
import ./crypto

type
  EntryKind* = enum
    ekFile = "file",    ## Regular file entry
    ekDir = "dir"      ## Directory entry (for future use)
  ## hash = SHA-256 of ciphertext blob; contentHash = SHA-256 of plaintext (optional, v4+).
  VaultEntry* = tuple[id, path, hash: string, kind: EntryKind, contentHash: string]

proc genId*(): string =
  ## 16-char random hex via cryptographic randomness.
  var buf: array[8, byte]
  doAssert urandom(buf)
  for b in buf:
    result.add(b.toHex(2).toLowerAscii())

proc expandHome*(p: string): string =
  ## Expand ~ to $HOME in path strings.
  if p.startsWith("~/"):
    result = getHomeDir() / p[2..^1]
  else:
    result = p

proc resolvePath*(cfg: GpgConfig, path: string): string =
  ## Resolve a manifest path to an absolute filesystem path.
  ## When cfg.root is set, paths are relative to root.
  ## Otherwise, ~/... paths are expanded via expandHome.
  if cfg.root.len > 0:
    cfg.root / path
  else:
    expandHome(path)

proc storePath*(cfg: GpgConfig, absPath: string, repo: string): string =
  ## Convert an absolute path to the stored manifest format.
  ## When cfg.root is set, stores relative to root.
  ## Otherwise, stores with ~/ prefix if under HOME.
  if cfg.root.len > 0:
    relativePath(absPath, cfg.root)
  elif absPath.startsWith(getHomeDir()):
    "~/" & relativePath(absPath, getHomeDir())
  else:
    absPath

proc isPathSafe*(cfg: GpgConfig, manifestPath: string): bool =
  ## Validate that a manifest path resolves within expected boundaries.
  ## Returns false for directory traversal attempts (e.g. ../../etc/passwd).
  let resolved = normalizedPath(resolvePath(cfg, manifestPath))
  if cfg.root.len > 0:
    let root = normalizedPath(cfg.root)
    resolved == root or resolved.startsWith(root & "/")
  elif manifestPath.startsWith("~/"):
    let home = normalizedPath(getHomeDir()).strip(leading = false, trailing = true, chars = {'/'})
    resolved.startsWith(home & "/")
  else:
    true  # absolute paths: user explicitly provided, their responsibility

proc vaultDir*(repo: string): string =
  ## Path to the .vault directory within a repo.
  repo / ".vault"

proc loadManifest*(repo: string, verifySig = false,
                   cfg = GpgConfig()): seq[VaultEntry] =
  ## Decrypt and parse the vault manifest.
  ## Returns empty seq if no manifest exists.
  ## Supports v1–v4 (v4 adds plaintext contentHash for fast `status`).
  ##
  ## `cfg` is optional so the many call sites that only read a gpg vault stay
  ## unchanged. `findManifest` still refuses to report a vault sealed by the
  ## other backend as empty, so omitting it fails loudly rather than quietly.
  let enc = findManifest(repo, cfg)
  if enc.len == 0:
    return @[]
  verifyManifest(cfg, enc, verifySig)
  let plain = decryptToString(cfg, enc, verifySig)
  for line in plain.splitLines:
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('\t')
    if parts.len == 2:
      # v1: id\tpath
      result.add((parts[0], parts[1], "", ekFile, ""))
    elif parts.len == 3:
      # v2: id\tpath\thash
      result.add((parts[0], parts[1], parts[2], ekFile, ""))
    elif parts.len == 4:
      # v3: id\tpath\thash\tkind
      let kind = if parts[3] == "dir": ekDir else: ekFile
      result.add((parts[0], parts[1], parts[2], kind, ""))
    elif parts.len >= 5:
      # v4: id\tpath\thash\tkind\tcontentHash
      let kind = if parts[3] == "dir": ekDir else: ekFile
      result.add((parts[0], parts[1], parts[2], kind, parts[4]))

proc saveManifest*(repo: string, entries: seq[VaultEntry], cfg: GpgConfig) =
  ## Serialize entries (v4: blob hash, kind, plaintext content hash) and encrypt.
  let plainPath = vaultDir(repo) / ".manifest.plain"
  let encPath = manifestPath(repo, cfg)
  var content = "# vault-manifest-v4\n"
  for e in entries:
    content.add(&"{e.id}\t{e.path}\t{e.hash}\t{e.kind}\t{e.contentHash}\n")
  writeFile(plainPath, content)
  encryptFile(cfg, plainPath, encPath)
  removeFile(plainPath)
  # The manifest is the trust root: its hashes are what vouch for every blob,
  # so it is the one thing that has to be signed when the backend cannot.
  signManifest(cfg, encPath)
