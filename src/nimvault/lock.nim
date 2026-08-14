## Cross-process lock over one vault.
##
## Every mutating command rewrites `.vault/manifest.gpg` from a copy it read
## moments earlier. Two of them at once is a lost update: both read the same
## entries, both write, and whichever finishes last silently drops the other's
## work, leaving that blob orphaned on disk with no entry pointing at it. That
## is not hypothetical on a machine running several agents and editors that can
## each shell out to nimvault.
##
## The lock is an `fcntl` write lock. The kernel drops it when the process
## exits, including on a crash or a kill, so there is no stale lock to reason
## about and nothing to clean up by hand.
##
## It lives under the runtime directory rather than in `.vault`, so a vault
## checkout never gains an untracked file and a read-only checkout can still be
## locked. Runtime state is per-user and cleared on logout, which is exactly the
## lifetime a lock wants.
##
## Scope: `fcntl` records are held per process, so this excludes other nimvault
## *processes*, which is what the CLI and the MCP server are. It does not make
## two threads inside one process mutually exclusive; an in-process caller that
## needs that has to serialise itself.

import std/[os, posix, strformat]
import ./gpg

type VaultLock* = object
  fd: cint
  path: string

proc lockDir(): string =
  let xdg = getEnv("XDG_RUNTIME_DIR")
  if xdg.len > 0 and dirExists(xdg):
    xdg / "nimvault"
  else:
    getTempDir() / &"nimvault-{getuid()}"

proc lockPath*(repo: string): string =
  ## One lock per vault, named by the resolved repo path so two checkouts of
  ## the same project do not share one.
  let key = sha256sumBytes(expandFilename(repo))
  lockDir() / (key & ".lock")

proc release*(l: var VaultLock) =
  ## Drop the lock. Safe to call twice; the kernel would release on exit anyway.
  if l.fd >= 0:
    discard close(l.fd)
    l.fd = -1

proc `=destroy`(l: VaultLock) =
  ## Releasing on scope exit is what lets a command take the lock in one line
  ## without a wrapper block, and it still holds when the body raises.
  if l.fd >= 0:
    discard close(l.fd)

proc `=copy`(dst: var VaultLock, src: VaultLock) {.error:
  "VaultLock owns a file descriptor; move it or take a new one".}

proc tryAcquire(fd: cint): bool =
  var fl: Tflock
  fl.l_type = F_WRLCK.cshort
  fl.l_whence = SEEK_SET.cshort
  fl.l_start = 0
  fl.l_len = 0        # whole file
  fcntl(fd, F_SETLK, addr fl) != -1

proc acquire*(repo: string, timeoutMs = 30_000): VaultLock =
  ## Take the vault lock, waiting up to `timeoutMs` for a holder to finish.
  ##
  ## Waiting rather than failing at once is deliberate: the common contention is
  ## two short commands overlapping, and failing there would push a pointless
  ## retry onto the caller.
  let dir = lockDir()
  if not dirExists(dir):
    createDir(dir)
  let path = lockPath(repo)
  let fd = open(path.cstring, O_RDWR or O_CREAT, 0o600.Mode)
  if fd < 0:
    nvRaise(&"FATAL: cannot open vault lock: {path}")

  result = VaultLock(fd: fd, path: path)
  const stepMs = 50
  var waited = 0
  while not tryAcquire(fd):
    if waited >= timeoutMs:
      discard close(fd)
      result.fd = -1
      nvRaise(&"FATAL: vault is locked by another nimvault process " &
              &"(waited {timeoutMs} ms)")
    sleep(stepMs)
    waited += stepMs

template withVaultLock*(repo: string, body: untyped) =
  ## Run `body` as the only process mutating this vault.
  var lk = acquire(repo)
  try:
    body
  finally:
    release(lk)
