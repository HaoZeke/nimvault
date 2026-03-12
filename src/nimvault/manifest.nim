## Vault manifest operations: entry types, load/save, ID generation.

import std/[os, strutils, strformat, sysrand]
import ./gpg

type
  EntryKind* = enum
    ekFile = "file",    ## Regular file entry
    ekDir = "dir"      ## Directory entry (for future use)
  VaultEntry* = tuple[id, path, hash: string, kind: EntryKind]

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

proc loadManifest*(repo: string, verifySig = false): seq[VaultEntry] =
  ## Decrypt and parse the vault manifest.
  ## Returns empty seq if no manifest exists.
  ## Supports v1 (id\tpath), v2 (id\tpath\thash), and v3 (id\tpath\thash\tkind) formats.
  let enc = vaultDir(repo) / "manifest.gpg"
  if not fileExists(enc):
    return @[]
  let plain = gpgDecryptToString(enc, verifySig)
  for line in plain.splitLines:
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('\t')
    if parts.len == 2:
      # v1 format: id\tpath (default to file)
      result.add((parts[0], parts[1], "", ekFile))
    elif parts.len == 3:
      # v2 format: id\tpath\thash (default to file)
      result.add((parts[0], parts[1], parts[2], ekFile))
    elif parts.len >= 4:
      # v3 format: id\tpath\thash\tkind
      let kind = if parts[3] == "dir": ekDir else: ekFile
      result.add((parts[0], parts[1], parts[2], kind))

proc saveManifest*(repo: string, entries: seq[VaultEntry], cfg: GpgConfig) =
  ## Serialize entries (v3 format with hashes and kind) and encrypt as the vault manifest.
  let plainPath = vaultDir(repo) / ".manifest.plain"
  let encPath = vaultDir(repo) / "manifest.gpg"
  var content = "# vault-manifest-v3\n"
  for e in entries:
    content.add(&"{e.id}\t{e.path}\t{e.hash}\t{e.kind}\n")
  writeFile(plainPath, content)
  gpgEncrypt(cfg, plainPath, encPath)
  removeFile(plainPath)
