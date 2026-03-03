## CLI dispatch for nimvault using cligen.
##
## Each subcommand is a thin wrapper proc prefixed with `do` to avoid
## name collisions (cligen macros operate on typed AST). The `cmdName`
## parameter maps them to the desired subcommand names.

import std/[osproc, strutils]
import cligen

from ./gpg import GpgConfig, initGpgConfig
from ./commands import nil

const Version = "0.2.0"

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
    [doRm, cmdName = "rm", positional = "path",
     help = {"path": "file path to remove", "recipient": rh}],
    [doMv, cmdName = "mv", positional = "paths",
     help = {"paths": "<old-path> <new-path>", "recipient": rh}],
    [doList, cmdName = "list", help = {"recipient": rh}],
    [doStatus, cmdName = "status", help = {"recipient": rh}],
  )
