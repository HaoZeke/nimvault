## Vault manifest operations: entry types, load/save, ID generation.

import std/[os, strutils, strformat, sysrand]
import ./gpg

type
  VaultEntry* = tuple[id, path: string]

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

proc vaultDir*(repo: string): string =
  ## Path to the .vault directory within a repo.
  repo / ".vault"

proc loadManifest*(repo: string): seq[VaultEntry] =
  ## Decrypt and parse the vault manifest.
  ## Returns empty seq if no manifest exists.
  let enc = vaultDir(repo) / "manifest.gpg"
  if not fileExists(enc):
    return @[]
  let plain = gpgDecryptToString(enc)
  for line in plain.splitLines:
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('\t', maxsplit = 1)
    if parts.len == 2:
      result.add((parts[0], parts[1]))

proc saveManifest*(repo: string, entries: seq[VaultEntry], cfg: GpgConfig) =
  ## Serialize entries and encrypt as the vault manifest.
  let plainPath = vaultDir(repo) / ".manifest.plain"
  let encPath = vaultDir(repo) / "manifest.gpg"
  var content = "# vault-manifest-v1\n"
  for e in entries:
    content.add(&"{e.id}\t{e.path}\n")
  writeFile(plainPath, content)
  gpgEncrypt(cfg, plainPath, encPath)
  removeFile(plainPath)
