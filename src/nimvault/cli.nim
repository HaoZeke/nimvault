## CLI dispatch for nimvault using cligen.

import std/[os, strutils, strformat, json]
import cligen

from ./gpg import GpgConfig, initGpgConfig, NimvaultError, nvNonInteractive
from ./vaultrepo import resolveVaultRepo, warnIfRootIsAmbiguous, gitRoot
from ./commands import nil
from ./version import Version
export Version

template cliRun(body: untyped) =
  try:
    body
  except NimvaultError as e:
    stderr.writeLine e.msg
    quit (if e.code <= 0: 1 else: e.code)
  except CatchableError as e:
    stderr.writeLine "FATAL: " & e.msg
    quit 1

template cliRunJson(asJson: bool, body: untyped) =
  ## JSON commands print one object on stdout. A failure is that object with
  ## `ok: false`, and the same message on stderr.
  try:
    body
  except NimvaultError as e:
    if asJson:
      stdout.write($( %* {"ok": false, "error": e.msg} ) & "\n")
    stderr.writeLine e.msg
    quit (if e.code <= 0: 1 else: e.code)
  except CatchableError as e:
    if asJson:
      stdout.write($( %* {"ok": false, "error": e.msg} ) & "\n")
    stderr.writeLine "FATAL: " & e.msg
    quit 1

proc resolve(recipient: string, vault = ""): (string, GpgConfig) =
  ## The vault repository need not be the one you are standing in; see
  ## `vaultrepo`. Everything else keys off whatever it resolves to.
  let repo = resolveVaultRepo(vault)
  let cfg = initGpgConfig(recipient, repo)
  warnIfRootIsAmbiguous(repo, cfg.root)
  (repo, cfg)

proc prepare(recipient, vault: string, publicOnly, noninteractive: bool): (string, GpgConfig) =
  if noninteractive or getEnv("NIMVAULT_NONINTERACTIVE") == "1":
    nvNonInteractive = true
  let (repo, cfg0) = resolve(recipient, vault)
  var cfg = cfg0
  if publicOnly or getEnv("NIMVAULT_PUBLIC_ONLY") == "1":
    cfg.publicOnly = true
  (repo, cfg)

proc doSeal(recipient = "", force = false, vault = "", publicOnly = false,
            noninteractive = false) =
  ## Unchanged files keep their existing blob; `--force` re-encrypts every one.
  ## `--public-only` appends without a secret key and without reading the manifest.
  cliRun:
    let (repo, cfg) = prepare(recipient, vault, publicOnly, noninteractive)
    commands.seal(repo, cfg, force)

proc doUnseal(path: seq[string] = @[], recipient = "", allowUnsigned = false,
              vault = "") =
  ## With no path this restores the whole vault, which is the long-standing
  ## behaviour. Naming paths restores only those, and a directory restores
  ## everything beneath it.
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.unseal(repo, cfg, allowUnsigned, path)

proc doAdd(path: seq[string], recipient = "", noGitignore = false, vault = "",
           publicOnly = false, noninteractive = false) =
  if path.len != 1:
    stderr.writeLine "usage: nimvault add <path>"
    quit 1
  cliRun:
    let (repo, cfg) = prepare(recipient, vault, publicOnly, noninteractive)
    commands.add(repo, path[0], cfg, noGitignore)

proc doAddDir(path: seq[string], recipient = "", noGitignore = false,
              vault = "", publicOnly = false, noninteractive = false) =
  if path.len != 1:
    stderr.writeLine "usage: nimvault add-dir <directory>"
    quit 1
  cliRun:
    let (repo, cfg) = prepare(recipient, vault, publicOnly, noninteractive)
    commands.addDir(repo, path[0], cfg, noGitignore)

proc doAdopt(path: seq[string] = @[], recipient = "", vault = "",
             noninteractive = false) =
  ## Sign unadopted `.vault/a/` entries into `.vault/e/`. Needs a secret key.
  ## A path that matches a signed record is refused.
  cliRun:
    let (repo, cfg) = prepare(recipient, vault, false, noninteractive)
    commands.adopt(repo, cfg, path)

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

proc doStatus(recipient = "", vault = "", json = false, noninteractive = false) =
  cliRunJson json:
    let (repo, cfg) = prepare(recipient, vault, false, noninteractive)
    if json:
      stdout.write commands.statusJson(repo, cfg)
    else:
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

proc doCheck(recipient = "", vault = "", json = false, noninteractive = false,
            publicOnly = false, digests = "", writeDigests = "") =
  ## Blob-vs-manifest consistency. Exits 2 when anything is off, so a
  ## pre-push hook or a continuous-integration job can gate on it.
  ## `--digests` compares ciphertext to a previous snapshot. No secret key
  ## is required for that, or for the blob-index.
  cliRun:
    let (repo, cfg) = prepare(recipient, vault, publicOnly, noninteractive)
    let code = commands.check(repo, cfg, digests, writeDigests, json)
    if code != 0:
      quit code

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

proc doWho(path: seq[string] = @[], recipient = "", vault = "", json = false,
          noninteractive = false) =
  ## With paths, print the wrap rule that would seal each one. That needs no
  ## secret key. With no paths, list the entries this identity can read.
  cliRunJson json:
    let (repo, cfg) = prepare(recipient, vault, false, noninteractive)
    if json:
      stdout.write commands.whoJson(repo, cfg, path)
    else:
      commands.who(repo, cfg, path)

proc doLock(recipient = "", vault = "") =
  cliRun:
    let (repo, cfg) = resolve(recipient, vault)
    commands.lockPlaintext(repo, cfg)

proc doInit(recipient = "", vault = "") =
  cliRun:
    let repo = resolveVaultRepo(vault)
    commands.initVault(repo, recipient)

proc doHook(recipient = "", vault = "") =
  cliRun:
    let repo = resolveVaultRepo(vault)
    commands.installHooks(repo)

proc doDoctor(recipient = "", vault = "", json = false, noninteractive = false,
             publicOnly = false) =
  cliRun:
    let (repo, cfg) = prepare(recipient, vault, publicOnly, noninteractive)
    let info = commands.doctorInfo(repo, cfg)
    if json:
      stdout.write commands.doctorJsonOf(info)
      if info.problems.len > 0:
        stderr.writeLine(&"doctor: {info.problems.len} problem(s)")
        quit 2
    elif info.problems.len > 0:
      stderr.writeLine info.text.strip()
      quit 2
    else:
      stdout.write info.text

proc doVersion() =
  ## Print package version (also via --version / -V before dispatch).
  echo "nimvault ", Version

proc main*(args: seq[string] = commandLineParams()) =
  ## Entry used by nimvault.nim when isMainModule.
  if getEnv("NIMVAULT_NONINTERACTIVE") == "1":
    nvNonInteractive = true
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
             "force": "re-encrypt every file, not only changed ones",
             "publicOnly": "append without a secret key; do not read the manifest",
             "noninteractive": "fail instead of prompting for a passphrase"}],
    [doUnseal, cmdName = "unseal", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "allowUnsigned": "accept an unsigned legacy manifest and write unadopted .vault/a/ entries; a path that matches a signed record is still refused",
             "path": "restore only these entries (default: all)"}],
    [doAdd, cmdName = "add", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "noGitignore": "do not append path to .gitignore",
             "publicOnly": "encrypt to public keys; do not read the manifest",
             "noninteractive": "fail instead of prompting for a passphrase"}],
    [doAddDir, cmdName = "add-dir", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "noGitignore": "do not append paths to .gitignore",
             "publicOnly": "encrypt to public keys; do not read the manifest",
             "noninteractive": "fail instead of prompting for a passphrase"}],
    [doRm, cmdName = "rm", positional = "path", help = {"recipient": rh, "vault": vh}],
    [doAdopt, cmdName = "adopt", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "path": "sign only these unadopted fragments (default: all)",
             "noninteractive": "fail instead of prompting for a passphrase"}],
    [doGet, cmdName = "get", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "allowUnsigned": "return an unadopted .vault/a/ fragment; a path that matches a signed record is still refused"}],
    [doMv, cmdName = "mv", positional = "paths", help = {"recipient": rh, "vault": vh}],
    [doList, cmdName = "list", help = {"recipient": rh, "vault": vh}],
    [doStatus, cmdName = "status",
     help = {"recipient": rh, "vault": vh,
             "json": "print one JSON object on stdout",
             "noninteractive": "fail instead of prompting for a passphrase"}],
    [doCheck, cmdName = "check",
     help = {"recipient": rh, "vault": vh,
             "json": "print one JSON object on stdout",
             "noninteractive": "fail instead of prompting for a passphrase",
             "publicOnly": "compare blobs to the blob-index, not the manifest",
             "digests": "previous digest list to diff against",
             "writeDigests": "write a digest list of the ciphertext on disk"}],
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
    [doWho, cmdName = "who", positional = "path",
     help = {"recipient": rh, "vault": vh,
             "path": "ask which rule seals these paths (no secret key)",
             "json": "print one JSON object on stdout",
             "noninteractive": "fail instead of prompting for a passphrase"}],
    [doLock, cmdName = "lock",
     help = {"recipient": rh, "vault": vh}],
    [doInit, cmdName = "init",
     help = {"recipient": rh, "vault": vh}],
    [doHook, cmdName = "hook",
     help = {"recipient": rh, "vault": vh}],
    [doDoctor, cmdName = "doctor",
     help = {"recipient": rh, "vault": vh,
             "json": "print one JSON object on stdout",
             "noninteractive": "fail instead of prompting for a passphrase",
             "publicOnly": "do not use a secret key"}],
    [doRm, cmdName = "remove", positional = "path",
     help = {"recipient": rh, "vault": vh}],
    [doVersion, cmdName = "version"],
  )

when isMainModule:
  main()
