## CLI dispatch for nimvault using cligen.

import std/[os, osproc, strutils]
import cligen

from ./gpg import GpgConfig, initGpgConfig, NimvaultError
from ./commands import nil

const Version* = "0.4.2"

template cliRun(body: untyped) =
  try:
    body
  except NimvaultError as e:
    stderr.writeLine e.msg
    quit 1
  except CatchableError as e:
    stderr.writeLine "FATAL: " & e.msg
    quit 1

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
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.seal(repo, cfg)

proc doUnseal(path: seq[string] = @[], recipient = "", allowUnsigned = false) =
  ## With no path this restores the whole vault, which is the long-standing
  ## behaviour. Naming paths restores only those, and a directory restores
  ## everything beneath it.
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.unseal(repo, cfg, allowUnsigned, path)

proc doAdd(path: seq[string], recipient = "", noGitignore = false) =
  if path.len != 1:
    stderr.writeLine "usage: nimvault add <path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.add(repo, path[0], cfg, noGitignore)

proc doAddDir(path: seq[string], recipient = "", noGitignore = false) =
  if path.len != 1:
    stderr.writeLine "usage: nimvault add-dir <directory>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.addDir(repo, path[0], cfg, noGitignore)

proc doGet(path: seq[string], recipient = "", allowUnsigned = false) =
  ## Print one entry's plaintext on stdout. Deliberately quiet: the output is
  ## meant to be read by another program, so nothing decorative may share the
  ## stream with a secret.
  if path.len != 1:
    stderr.writeLine "usage: nimvault get <path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient)
    stdout.write(commands.get(repo, path[0], cfg, allowUnsigned))

proc doRm(path: seq[string], recipient = "") =
  if path.len != 1:
    stderr.writeLine "usage: nimvault rm <path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.remove(repo, path[0], cfg)

proc doMv(paths: seq[string], recipient = "") =
  if paths.len != 2:
    stderr.writeLine "usage: nimvault mv <old-path> <new-path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.move(repo, paths[0], paths[1], cfg)

proc doList(recipient = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.list(repo, cfg)

proc doStatus(recipient = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient)
    commands.status(repo, cfg)

proc doScan(path: seq[string], recipient = "", vault = "") =
  let targetArg = if path.len == 0: "." else: path[0]
  cliRun:
    let (repo, cfg) = resolve(recipient)
    let target = if targetArg.isAbsolute: targetArg else: getCurrentDir() / targetArg
    commands.scan(repo, target, cfg)

proc doVersion() =
  ## Print package version (also via --version / -V before dispatch).
  echo "nimvault ", Version

proc main*(args: seq[string] = commandLineParams()) =
  ## Entry used by nimvault.nim when isMainModule.
  # Early version flags — cligen's multi-dispatch does not wire package version by default.
  for a in args:
    if a in ["--version", "-V", "version"]:
      doVersion()
      return
  const rh = "GPG recipient key id (or use .vault/config / NIMVAULT_GPG_RECIPIENT)"
  dispatchMulti(
    [doSeal, cmdName = "seal", help = {"recipient": rh}],
    [doUnseal, cmdName = "unseal", positional = "path",
     help = {"recipient": rh,
             "allowUnsigned": "accept unsigned legacy manifests",
             "path": "restore only these entries (default: all)"}],
    [doAdd, cmdName = "add", positional = "path",
     help = {"recipient": rh, "noGitignore": "do not append path to .gitignore"}],
    [doAddDir, cmdName = "add-dir", positional = "path",
     help = {"recipient": rh, "noGitignore": "do not append paths to .gitignore"}],
    [doRm, cmdName = "rm", positional = "path", help = {"recipient": rh}],
    [doGet, cmdName = "get", positional = "path",
     help = {"recipient": rh,
             "allowUnsigned": "accept unsigned legacy manifests"}],
    [doMv, cmdName = "mv", positional = "paths", help = {"recipient": rh}],
    [doList, cmdName = "list", help = {"recipient": rh}],
    [doStatus, cmdName = "status", help = {"recipient": rh}],
    [doScan, cmdName = "scan", positional = "path",
     help = {"recipient": rh, "vault": "vault repo override"}],
    [doVersion, cmdName = "version"],
  )

when isMainModule:
  main()
