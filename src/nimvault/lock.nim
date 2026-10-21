## Cross-process lock over one vault.
##
## Every mutating command rewrites the trust root from a copy it read moments
## earlier. Two of them at once is a lost update: both read the same entries,
## both write, and whichever finishes last silently drops the other's work.
##
## The lock is an `fcntl` write lock plus a process-wide mutex. `fcntl` keeps
## other processes out. The mutex keeps other threads in this process out:
## POSIX locks are owned by the process, so a second thread's `F_SETLK` would
## succeed while the first still holds the file. The kernel drops the `fcntl`
## lock when the process exits, including on a crash or a kill.
##
## It lives under the runtime directory rather than in `.vault`, so a vault
## checkout never gains an untracked file and a read-only checkout can still be
## locked. Runtime state is per-user and cleared on logout, which is exactly the
## lifetime a lock wants.
##
## Closing any descriptor of the lock file drops every lock this process holds
## on it, so the descriptor stays open until the mutex is about to be released,
## and a moved-from lock must not close descriptor 0.

import std/[os, posix, strformat]
import std/locks as thrlocks
import ./gpg
import ./crypto

type VaultLock* = object
  fd: cint
  path: string
  owns: bool

var threadGate: thrlocks.Lock
initLock(threadGate)

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

proc dropOwned(l: var VaultLock) =
  if not l.owns:
    l.fd = -1
    return
  if l.fd >= 0:
    discard close(l.fd)
    l.fd = -1
  l.owns = false
  thrlocks.release(threadGate)

proc release*(l: var VaultLock) =
  ## Drop the lock. Safe to call twice; the kernel would release on exit anyway.
  dropOwned(l)

when NimMajor == 2 and NimMinor == 0:
  proc `=destroy`(l: var VaultLock) =
    ## Nim 2.0 requires a mutable `=destroy` parameter.
    dropOwned(l)
else:
  proc `=destroy`(l: VaultLock) =
    ## Releasing on scope exit is what lets a command take the lock in one line
    ## without a wrapper block, and it still holds when the body raises.
    ## A moved-from lock has `owns` false, so this does not close descriptor 0.
    ## The descriptor is closed before the mutex: closing it drops every fcntl
    ## lock this process holds on the file.
    if not l.owns:
      return
    if l.fd >= 0:
      discard close(l.fd)
    thrlocks.release(threadGate)

proc `=wasMoved`(l: var VaultLock) =
  ## A bitwise reset would leave `fd` at 0 and the destructor would close stdin.
  l.fd = -1
  l.owns = false

proc `=copy`(dst: var VaultLock, src: VaultLock) {.error:
  "VaultLock owns a file descriptor; move it or take a new one".}

proc tryFlock(fd: cint): bool =
  var fl: Tflock
  fl.l_type = F_WRLCK.cshort
  fl.l_whence = SEEK_SET.cshort
  fl.l_start = 0
  fl.l_len = 0        # whole file
  fcntl(fd, F_SETLK, addr fl) != -1

proc takeGate(timeoutMs: int) =
  const stepMs = 50
  var waited = 0
  while not thrlocks.tryAcquire(threadGate):
    if waited >= timeoutMs:
      nvRaise(&"FATAL: vault is locked by another nimvault call " &
              &"(waited {timeoutMs} ms)")
    sleep(stepMs)
    waited += stepMs

proc acquire*(repo: string, timeoutMs = 30_000): VaultLock =
  ## Take the vault lock, waiting up to `timeoutMs` for a holder to finish.
  ##
  ## Waiting rather than failing at once is deliberate: the common contention is
  ## two short commands overlapping, and failing there would push a pointless
  ## retry onto the caller.
  takeGate(timeoutMs)
  var handed = false
  try:
    let dir = lockDir()
    ensureOwnerDir(dir)
    let path = lockPath(repo)
    let fd = open(path.cstring, O_RDWR or O_CREAT or O_CLOEXEC, 0o600.Mode)
    if fd < 0:
      nvRaise(&"FATAL: cannot open vault lock: {path}")

    result = VaultLock(fd: fd, path: path, owns: false)
    const stepMs = 50
    var waited = 0
    while not tryFlock(fd):
      if waited >= timeoutMs:
        discard close(fd)
        result.fd = -1
        nvRaise(&"FATAL: vault is locked by another nimvault call " &
                &"(waited {timeoutMs} ms)")
      sleep(stepMs)
      waited += stepMs
    result.owns = true
    handed = true
  finally:
    if not handed:
      thrlocks.release(threadGate)

template withVaultLock*(repo: string, body: untyped) =
  ## Run `body` as the only call mutating this vault.
  var lk = acquire(repo)
  try:
    body
  finally:
    release(lk)
