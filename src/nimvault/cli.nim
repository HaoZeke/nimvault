## CLI dispatch for nimvault using cligen.

import std/[os, strutils, posix]
import cligen

from ./gpg import GpgConfig, initGpgConfig, NimvaultError
from ./vaultrepo import resolveVaultRepo, warnIfRootIsAmbiguous, gitRoot
from ./commands import nil
from ./version import Version
export Version

template cliRun(body: untyped) =
  try:
    # cligen's default SIGPIPE handler exits 0. Restore the kernel default of
    # "write gets EPIPE" for each command run so a closed child pipe is a
    # command failure, never a silent success.
    discard sigignore(SIGPIPE)
    body
  except NimvaultError as e:
    stderr.writeLine e.msg
    quit 1
  except CatchableError as e:
    stderr.writeLine "FATAL: " & e.msg
    quit 1

proc resolve(recipient: string, vault = ""): (string, GpgConfig) =
  ## The vault repository need not be the one you are standing in; see
  ## `vaultrepo`. Everything else keys off whatever it resolves to.
  let repo = resolveVaultRepo(vault)
  let cfg = initGpgConfig(recipient, repo)
  warnIfRootIsAmbiguous(repo, cfg.root)
  (repo, cfg)

proc doSeal(recipient = "", force = false, vault = "") =
  ## Unchanged files keep their existing blob; `--force` re-encrypts every one.
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.seal(repo, cfg, force)

proc doUnseal(path: seq[string] = @[], recipient = "", allowUnsigned = false,
              vault = "") =
  ## With no path this restores the whole vault, which is the long-standing
  ## behaviour. Naming paths restores only those, and a directory restores
  ## everything beneath it.
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.unseal(repo, cfg, allowUnsigned, path)

proc doAdd(path: seq[string], recipient = "", noGitignore = false, vault = "") =
  if path.len != 1:
    stderr.writeLine "usage: nimvault add <path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.add(repo, path[0], cfg, noGitignore)

proc doAddDir(path: seq[string], recipient = "", noGitignore = false,
              vault = "") =
  if path.len != 1:
    stderr.writeLine "usage: nimvault add-dir <directory>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.addDir(repo, path[0], cfg, noGitignore)

proc doGet(path: seq[string], recipient = "", allowUnsigned = false, vault = "") =
  ## Print one entry's plaintext on stdout. Deliberately quiet: the output is
  ## meant to be read by another program, so nothing decorative may share the
  ## stream with a secret.
  if path.len != 1:
    stderr.writeLine "usage: nimvault get <path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    stdout.write(commands.get(repo, path[0], cfg, allowUnsigned))

proc doRm(path: seq[string], recipient = "", vault = "") =
  if path.len != 1:
    stderr.writeLine "usage: nimvault rm <path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.remove(repo, path[0], cfg)

proc doMv(paths: seq[string], recipient = "", vault = "") =
  if paths.len != 2:
    stderr.writeLine "usage: nimvault mv <old-path> <new-path>"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.move(repo, paths[0], paths[1], cfg)

proc doList(recipient = "", vault = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.list(repo, cfg)

proc doStatus(recipient = "", vault = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.status(repo, cfg)

proc doRotate(recipient = "", rekey = false, vault = "") =
  ## Rewrap the data keys to the current recipients. `--rekey` re-encrypts every
  ## payload instead, which is the only form that answers a key compromise.
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.rotate(repo, cfg, rekey)

proc doGc(recipient = "", dryRun = false, vault = "") =
  ## Remove blobs no manifest entry points at.
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.gc(repo, cfg, dryRun)

proc doCheck(recipient = "", vault = "") =
  ## Blob-vs-manifest consistency. Exits non-zero when anything is off, so a
  ## pre-push hook or a continuous-integration job can gate on it.
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.check(repo, cfg)

proc doScan(path: seq[string], recipient = "", vault = "", cached = false,
            rev = "", remote = "") =
  ## Walk a tree, or with `--cached` the index, or with `--rev` commits.
  ## `--cached` and `--rev` take no path: they read git, not the worktree.
  if (cached and rev.len > 0) or ((cached or rev.len > 0) and path.len > 0) or
     path.len > 1 or (remote.len > 0 and rev.len == 0):
    stderr.writeLine "usage: nimvault scan [PATH] [--cached | --rev REV [--remote NAME]]"
    quit 1
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    if cached or rev.len > 0:
      let here = gitRoot()
      let content = if here.len > 0: here else: repo
      if cached:
        commands.scanCached(repo, cfg, content)
      else:
        commands.scanRev(repo, cfg, content, rev, remote)
    else:
      let targetArg = if path.len == 0: "." else: path[0]
      let target = if targetArg.isAbsolute: targetArg else: getCurrentDir() / targetArg
      commands.scan(repo, target, cfg)

proc doWho(recipient = "", vault = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.who(repo, cfg)

proc doLock(recipient = "", allowUnsigned = false, vault = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.lockPlaintext(repo, cfg, allowUnsigned)

proc doInit(recipient = "", vault = "") =
  cliRun:
    let repo = resolveVaultRepo(vault)
    commands.initVault(repo, recipient)

proc doHook(recipient = "", vault = "") =
  cliRun:
    let repo = resolveVaultRepo(vault)
    commands.installHooks(repo)

proc doDoctor(recipient = "", vault = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.doctor(repo, cfg)

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
  const vh = "vault repository holding .vault/ (or NIMVAULT_VAULT_REPO, or a " &
             ".nimvault pointer file)"
  dispatchMulti(
    [doSeal, cmdName = "seal",
     help = {"recipient": rh, "vault": vh,
             "force": "re-encrypt every file, not only changed ones"}],
    [doUnseal, cmdName = "unseal", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "allowUnsigned": "accept records with no signature; a present one must verify",
             "path": "restore only these entries (default: all)"}],
    [doAdd, cmdName = "add", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "noGitignore": "do not append path to .gitignore"}],
    [doAddDir, cmdName = "add-dir", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "noGitignore": "do not append paths to .gitignore"}],
    [doRm, cmdName = "rm", positional = "path", help = {"recipient": rh, "vault": vh}],
    [doGet, cmdName = "get", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "allowUnsigned": "accept records with no signature; a present one must verify"}],
    [doMv, cmdName = "mv", positional = "paths", help = {"recipient": rh, "vault": vh}],
    [doList, cmdName = "list", help = {"recipient": rh, "vault": vh}],
    [doStatus, cmdName = "status", help = {"recipient": rh, "vault": vh}],
    [doCheck, cmdName = "check", help = {"recipient": rh, "vault": vh}],
    [doGc, cmdName = "gc",
     help = {"recipient": rh, "vault": vh,
             "dryRun": "list orphans without removing them"}],
    [doRotate, cmdName = "rotate",
     help = {"recipient": rh, "vault": vh,
             "rekey": "re-encrypt every payload, not just the key wrapping"}],
    [doScan, cmdName = "scan", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "cached": "scan the git index instead of the worktree",
             "rev": "scan blobs introduced by a commit or A..B range",
             "remote": "with --rev, skip commits this remote's tracking refs reach"}],
    [doWho, cmdName = "who",
     help = {"recipient": rh, "vault": vh}],
    [doLock, cmdName = "lock",
     help = {"recipient": rh, "vault": vh,
             "allowUnsigned": "accept records with no signature; a present one must verify"}],
    [doInit, cmdName = "init",
     help = {"recipient": rh, "vault": vh}],
    [doHook, cmdName = "hook",
     help = {"recipient": rh, "vault": vh}],
    [doDoctor, cmdName = "doctor",
     help = {"recipient": rh, "vault": vh}],
    [doRm, cmdName = "remove", positional = "path",
     help = {"recipient": rh, "vault": vh}],
    [doVersion, cmdName = "version"],
  )

when isMainModule:
  main()
