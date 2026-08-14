## Where `.vault/` lives, which need not be where the plaintext lives.
##
## The long-standing assumption was that the vault sits inside the repository
## you are standing in. That works until the repository is public, which is the
## common case for dotfiles: the ciphertext is then archived forever by anyone
## who clones or forks, and on GitHub it stays fetchable through the fork
## network even after a history rewrite. Rotating a key does not reach it and
## neither does `--rekey`, because both act on the working tree.
##
## Keeping the vault in a separate private repository removes that exposure for
## everything stored from then on. It is a bigger improvement than any feature,
## and it costs nothing at read time: the manifest already stores target paths
## as `~/...`, so entries do not care which repository the blobs came from.
##
## Resolution order, most explicit first:
##
## 1. `--vault DIR`
## 2. `NIMVAULT_VAULT_REPO`
## 3. a `.nimvault` pointer file in the current git repository
## 4. the current git repository, which is the behaviour that predates this

import std/[os, osproc, strutils, strformat]
import ./gpg

const PointerFile* = ".nimvault"

proc gitRoot*(): string =
  let (output, code) = execCmdEx("git rev-parse --show-toplevel")
  if code != 0:
    return ""
  output.strip()

proc expandUser(p: string): string =
  if p.startsWith("~/"): getHomeDir() / p[2 .. ^1] else: p

proc readPointer*(dir: string): string =
  ## First non-comment line of `<dir>/.nimvault`, or empty.
  ##
  ## The pointer lives in the *content* repository rather than in the vault,
  ## because a vault cannot tell you where to find itself.
  let f = dir / PointerFile
  if not fileExists(f):
    return ""
  for line in lines(f):
    let s = line.strip()
    if s.len == 0 or s.startsWith("#"):
      continue
    return expandUser(s)
  return ""

proc resolveVaultRepo*(cliVault = ""): string =
  ## Directory that owns `.vault/`. Raises when nothing can be resolved, since
  ## every alternative silently operates on the wrong vault.
  if cliVault.len > 0:
    result = expandUser(cliVault).absolutePath
  else:
    let env = getEnv("NIMVAULT_VAULT_REPO").strip()
    if env.len > 0:
      result = expandUser(env).absolutePath
    else:
      let here = gitRoot()
      if here.len > 0:
        let pointed = readPointer(here)
        result = if pointed.len > 0: pointed.absolutePath else: here
      else:
        result = ""

  if result.len == 0:
    nvRaise("FATAL: no vault repository.\n" &
            "  Run inside a git repository, or set NIMVAULT_VAULT_REPO, or " &
            "pass --vault DIR,\n  or add a .nimvault file naming the vault " &
            "repository.")
  if not dirExists(result):
    nvRaise(&"FATAL: vault repository does not exist: {result}")

proc warnIfRootIsAmbiguous*(vaultRepo, configuredRoot: string) =
  ## `root = repo` means "paths are relative to the repository". With the vault
  ## in its own repository that is ambiguous, and resolving it against the
  ## vault would silently point every entry at the wrong tree.
  if configuredRoot.len == 0:
    return
  let here = gitRoot()
  if here.len > 0 and here != vaultRepo:
    nvRaise("FATAL: `root` is set while the vault lives in another repository.\n" &
            &"  vault:   {vaultRepo}\n" &
            &"  content: {here}\n" &
            "  Relative paths would resolve against the wrong tree. Set `root` " &
            "to an absolute\n  path, or unset it so entries are stored with a " &
            "~/ prefix.")
