## CLI dispatch for nimvault using cligen.
##
## Each subcommand is a thin wrapper proc prefixed with `do` to avoid
## name collisions (cligen macros operate on typed AST). The `cmdName`
## parameter maps them to the desired subcommand names.

import std/[osproc, strutils]
import cligen

from ./gpg import GpgConfig, initGpgConfig
from ./commands import nil

const Version = "0.1.0"

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

proc doUnseal(recipient = "") =
  ## Decrypt all vault entries to their target locations.
  let (repo, cfg) = resolve(recipient)
  commands.unseal(repo, cfg)

proc doAdd(path: string, recipient = "") =
  ## Add a file to the vault by its target path.
  let (repo, cfg) = resolve(recipient)
  commands.add(repo, path, cfg)

proc doRm(path: string, recipient = "") =
  ## Remove a file from the vault.
  let (repo, cfg) = resolve(recipient)
  commands.remove(repo, path, cfg)

proc doMv(oldPath, newPath: string, recipient = "") =
  ## Move/rename a vault entry's target path.
  let (repo, cfg) = resolve(recipient)
  commands.move(repo, oldPath, newPath, cfg)

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
    [doUnseal, cmdName = "unseal", help = {"recipient": rh}],
    [doAdd, cmdName = "add", help = {"path": "file path to add", "recipient": rh}],
    [doRm, cmdName = "rm", help = {"path": "file path to remove", "recipient": rh}],
    [doMv, cmdName = "mv", help = {"oldPath": "current path", "newPath": "new path", "recipient": rh}],
    [doList, cmdName = "list", help = {"recipient": rh}],
    [doStatus, cmdName = "status", help = {"recipient": rh}],
  )
