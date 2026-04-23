## CLI dispatch for nimvault using cligen.
##
## Each subcommand is a thin wrapper proc prefixed with `do` to avoid
## name collisions (cligen macros operate on typed AST). The `cmdName`
## parameter maps them to the desired subcommand names.

import std/[os, osproc, strutils]
import cligen

from ./gpg import GpgConfig, initGpgConfig
from ./commands import nil

const Version = "0.4.0"

proc repoRoot(): string =
  let (output, code) = execCmdEx("git rev-parse --show-toplevel")
  if code != 0:
    stderr.writeLine "FATAL: not inside a git repository"
    quit 1
  result = output.strip()

proc resolve(recipient: string): (string, GpgConfig) =
  let repo = repoRoot()
  let cfg = initGpgConfig(recipient, repo)
  (repo, cfg)

proc doSeal(recipient = "") =
  ## Encrypt all vault entries from their plaintext locations.
  let (repo, cfg) = resolve(recipient)
  commands.seal(repo, cfg)

proc doUnseal(recipient = "", allowUnsigned = false) =
  ## Decrypt all vault entries to their target locations.
  let (repo, cfg) = resolve(recipient)
  commands.unseal(repo, cfg, allowUnsigned)

proc doAdd(path: seq[string], recipient = "", noGitignore = false) =
  ## Add a file to the vault by its target path.
  if path.len != 1:
    stderr.writeLine "usage: nimvault add <path>"
    quit 1
  let (repo, cfg) = resolve(recipient)
  commands.add(repo, path[0], cfg, noGitignore)

proc doAddDir(path: seq[string], recipient = "", noGitignore = false) =
  ## Add a directory recursively to the vault.
  if path.len != 1:
    stderr.writeLine "usage: nimvault add-dir <directory>"
    quit 1
  let (repo, cfg) = resolve(recipient)
  commands.addDir(repo, path[0], cfg, noGitignore)

proc doRm(path: seq[string], recipient = "") =
  ## Remove a file from the vault.
  if path.len != 1:
    stderr.writeLine "usage: nimvault rm <path>"
    quit 1
  let (repo, cfg) = resolve(recipient)
  commands.remove(repo, path[0], cfg)

proc doMv(paths: seq[string], recipient = "") =
  ## Move/rename a vault entry's target path. Takes <old-path> <new-path>.
  if paths.len != 2:
    stderr.writeLine "usage: nimvault mv <old-path> <new-path>"
    quit 1
  let (repo, cfg) = resolve(recipient)
  commands.move(repo, paths[0], paths[1], cfg)

proc doList(recipient = "") =
  ## List all vault entries (id + path).
  let (repo, cfg) = resolve(recipient)
  commands.list(repo, cfg)

proc doStatus(recipient = "") =
  ## Show sync status of all vault entries.
  let (repo, cfg) = resolve(recipient)
  commands.status(repo, cfg)

proc doScan(path: seq[string], recipient = "") =
  ## Scan a file or directory for unvaulted secrets.
  ##
  ## Resolves the target's own git root (not cwd). When the target lives in
  ## a vault-enabled repo, vaulted files are skipped; otherwise everything
  ## is scanned. Never requires GPG config for scan-only mode.
  let targetArg = if path.len == 0: "." else: path[0]
  let absTarget = if targetArg.isAbsolute: targetArg
                  elif targetArg.startsWith("~/"):
                    getHomeDir() / targetArg[2..^1]
                  else: absolutePath(targetArg)
  let baseDir = if dirExists(absTarget): absTarget
                elif fileExists(absTarget): parentDir(absTarget)
                else: getCurrentDir()
  let (output, code) = execCmdEx("git -C " & quoteShell(baseDir) &
                                 " rev-parse --show-toplevel")
  if code == 0:
    let repo = output.strip()
    # Try to load GPG config; if unavailable, scan without manifest skip.
    try:
      let cfg = initGpgConfig(recipient, repo)
      commands.scan(repo, absTarget, cfg)
      return
    except CatchableError:
      discard
  commands.scan("", absTarget, GpgConfig())

const rh = "GPG recipient key (overrides env/config)"

proc main*() =
  clCfg.version = Version
  dispatchMulti(
    ["multi", doc = "GPG-encrypted opaque-blob vault with hidden filenames",
     cmdName = "nimvault"],
    [doSeal, cmdName = "seal", help = {"recipient": rh}],
    [doUnseal, cmdName = "unseal", help = {"recipient": rh,
      "allowUnsigned": "accept unsigned v1 vaults (skips signature checks)"}],
    [doAdd, cmdName = "add", positional = "path",
     help = {"path": "file path to add", "recipient": rh,
             "noGitignore": "skip auto-append to .gitignore"}],
    [doAddDir, cmdName = "add-dir", positional = "path",
     help = {"path": "directory path to add recursively", "recipient": rh,
             "noGitignore": "skip auto-append to .gitignore"}],
    [doRm, cmdName = "rm", positional = "path",
     help = {"path": "file path to remove", "recipient": rh}],
    [doMv, cmdName = "mv", positional = "paths",
     help = {"paths": "<old-path> <new-path>", "recipient": rh}],
    [doList, cmdName = "list", help = {"recipient": rh}],
    [doStatus, cmdName = "status", help = {"recipient": rh}],
    [doScan, cmdName = "scan", positional = "path",
     help = {"path": "file or directory to scan (default: repo root)",
             "recipient": rh}],
  )
