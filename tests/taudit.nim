## Behaviour the vault must keep: a failed seal, a symlink, a hook, a lock.
##
## Throwaway GPG home. No long-lived key material.

import std/[os, osproc, posix, strutils, strformat, streams, tables, tempfiles, times]
import nimvault/[gpg, manifest, commands, crypto, dek, lock]

proc gpgHome(tag: string): string =
  ## A GNUPGHOME for one test. gpg-agent puts its sockets in it, and macOS
  ## caps a socket path at 103 bytes, 49 of them its temp dir.
  result = createTempDir("nvg_", "_" & tag)
  setFilePermissions(result, {fpUserRead, fpUserWrite, fpUserExec})

proc setupGpg(): tuple[home, key: string] =
  result.home = gpgHome("gpg")
  putEnv("GNUPGHOME", result.home)
  let script = result.home / "keygen.txt"
  writeFile(script, """
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: NimVault Audit
Name-Email: audit@nimvault.local
Expire-Date: 0
%commit
""")
  let (output, code) = execCmdEx(&"gpg --batch --gen-key {script.quoteShell}")
  doAssert code == 0, output
  let (listed, lcode) = execCmdEx(
    "gpg --list-keys --keyid-format long --with-colons audit@nimvault.local")
  doAssert lcode == 0, listed
  for line in listed.splitLines:
    if line.startsWith("pub:"):
      let parts = line.split(':')
      if parts.len > 4:
        result.key = parts[4]
  doAssert result.key.len > 0, "no test key id"

proc setupRepo(): string =
  result = createTempDir("nimvault_audit_", "_repo")
  doAssert execCmdEx("git init -q", workingDir = result).exitCode == 0
  writeFile(result / ".gitkeep", "")
  doAssert execCmdEx("git add . && git commit -q -m init",
                     workingDir = result).exitCode == 0

proc genKey(home, name, email: string): string
proc cliExe(): string

proc gitCode(repo: string, args: seq[string]): int =
  let p = startProcess("git", args = @["-C", repo] & args,
                       options = {poUsePath, poStdErrToStdOut})
  discard p.outputStream.readAll()
  result = p.waitForExit()
  p.close()

proc devOf(path: string): int64 =
  var st: Stat
  if stat(path.cstring, st) != 0:
    return -1
  int64(st.st_dev)

proc secondFs(name: string): string =
  ## A fresh directory on a filesystem other than the temp dir's, or "" when
  ## this machine has none to offer.
  if not dirExists("/dev/shm"):
    return ""
  result = "/dev/shm" / (name & $getCurrentProcessId())
  createDir(result)
  setFilePermissions(result, {fpUserRead, fpUserWrite, fpUserExec})
  if devOf(result) == devOf(getTempDir()):
    removeDir(result)
    result = ""

let creds = setupGpg()
let keyId = creds.key

block lockKeepsPlaintextWhenBlobIsGone:
  ## lock is not a way to destroy the only remaining copy.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "only-copy")
  add(r, f, c)
  seal(r, c)
  let entries = loadManifest(r, cfg = c)
  doAssert entries.len == 1
  let blob = findBlob(r, c, entries[0].id)
  removeFile(blob)
  var raised = false
  try:
    lockPlaintext(r, c)
  except CatchableError:
    raised = true
  doAssert raised, "lock must refuse when the blob is missing"
  doAssert fileExists(f), "lock must leave the plaintext when the blob is gone"
  removeDir(r)
  echo "PASS: lock refuses to delete plaintext whose blob is missing"

block lockRemovesEditorBackups:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "lock-body")
  add(r, f, c)
  seal(r, c)
  let backup = f & "~"
  let autosave = f.parentDir / ("#" & f.extractFilename & "#")
  let swap = f.parentDir / ("." & f.extractFilename & ".swp")
  writeFile(backup, "backup-of-secret")
  writeFile(autosave, "autosave-of-secret")
  writeFile(swap, "vim-swap-of-secret")
  lockPlaintext(r, c)
  doAssert not fileExists(f), "lock removes the sealed plaintext"
  doAssert not fileExists(backup), "lock removes the editor backup"
  doAssert not fileExists(autosave), "lock removes the editor autosave"
  doAssert not fileExists(swap), "lock removes the editor swap file"
  unseal(r, c, allowUnsigned = true)
  doAssert readFile(f) == "lock-body"
  removeDir(r)
  echo "PASS: lock removes editor backups of an in-sync file"

block lockRequiresUnsignedFlagWhenSignerIsNone:
  ## lock must require the same signature policy as unseal.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "lock-none-signer")
  add(r, f, c)
  seal(r, c)
  var none = c
  none.signer = "none"
  var raised = false
  var msg = ""
  try:
    lockPlaintext(r, none)
  except CatchableError as e:
    raised = true
    msg = e.msg
  doAssert raised, "lock must refuse signer=none without --allow-unsigned"
  doAssert "signature required" in msg, msg
  doAssert fileExists(f), "a refused lock must keep the plaintext"
  lockPlaintext(r, none, allowUnsigned = true)
  doAssert not fileExists(f),
    "lock --allow-unsigned should remove in-sync plaintext for signer=none"
  removeDir(r)
  echo "PASS: lock requires --allow-unsigned when signer=none"

proc forgeUnsignedRecord(r: string, c: GpgConfig, id, path: string) =
  ## What anyone with push access can commit: a junk blob and a record that
  ## names it, encrypted to the vault key and signed by nobody.
  createDir(r / ".vault")
  let blob = crypto.blobPath(r, c, id)
  writeFile(blob, "junk-" & id)
  let work = createTempDir("nimvault_audit_", "_forge")
  let plain = work / "record.plain"
  writeFile(plain, EntryHeader & "\n" &
    &"{id}\t{path}\t{sha256sum(blob)}\tfile\t{sha256sumBytes(id)}\t" &
    repeat('0', 64) & "\n")
  createDir(entryDir(r))
  encryptFileTo(c, @[c.recipient], plain, entryFile(r, c, id), sign = false)
  removeDir(work)

block lockIgnoresForgedRecords:
  ## A forged record must not steer lock into shredding files it names.
  let oldHome = getEnv("HOME")
  let base = createTempDir("nimvault_audit_", "_home")
  let home = base / "home"
  createDir(home)
  createDir(base / "outside")
  let r = setupRepo()
  putEnv("HOME", home)
  try:
    let c = GpgConfig(recipient: keyId)
    let thesisBackup = home / "thesis.tex~"
    let outsideBackup = base / "outside" / "notes~"
    writeFile(thesisBackup, "thesis-draft")
    writeFile(outsideBackup, "outside-notes")
    forgeUnsignedRecord(r, c, "aaaaaaaaaaaaaaaa", "~/thesis.tex")
    forgeUnsignedRecord(r, c, "bbbbbbbbbbbbbbbb", "~/../outside/notes")
    var raised = false
    try:
      lockPlaintext(r, c)
    except CatchableError:
      raised = true
    doAssert raised, "lock must refuse unsigned records"
    doAssert readFile(thesisBackup) == "thesis-draft",
      "lock must not shred a backup named by an unsigned record"
    doAssert readFile(outsideBackup) == "outside-notes",
      "lock must not shred a backup outside HOME"

    # With `signer = none` the records load. Neither entry is present, so
    # neither backup belongs to an in-sync file, and the traversal is refused.
    var unsigned = c
    unsigned.signer = "none"
    dropEntryRecord(r, c, "bbbbbbbbbbbbbbbb")
    lockPlaintext(r, unsigned, allowUnsigned = true)
    doAssert readFile(thesisBackup) == "thesis-draft",
      "lock must not shred backups of an entry that is not present"
    forgeUnsignedRecord(r, c, "bbbbbbbbbbbbbbbb", "~/../outside/notes")
    raised = false
    try:
      lockPlaintext(r, unsigned, allowUnsigned = true)
    except CatchableError:
      raised = true
    doAssert raised, "lock must refuse a record path that climbs out of HOME"
    doAssert readFile(outsideBackup) == "outside-notes"
    doAssert readFile(thesisBackup) == "thesis-draft"
  finally:
    putEnv("HOME", oldHome)
    removeDir(r)
    removeDir(base)
  echo "PASS: lock ignores forged records and absent entries"

block unsealDoesNotFollowAncestorSymlink:
  ## A symlink above a not-yet-created directory must not receive the plaintext.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  createDir(r / "nested" / "deep")
  let f = r / "nested" / "deep" / "secret.txt"
  writeFile(f, "sym-secret")
  add(r, f, c)
  seal(r, c)
  removeFile(f)
  removeDir(r / "nested" / "deep")
  removeDir(r / "nested")
  let outside = createTempDir("nimvault_audit_", "_out")
  createSymlink(outside, r / "nested")
  var raised = false
  try:
    unseal(r, c, allowUnsigned = true)
  except CatchableError:
    raised = true
  doAssert raised, "unseal must refuse a symlink ancestor"
  doAssert not fileExists(outside / "deep" / "secret.txt"),
    "plaintext must not be written through the symlink"
  doAssert not dirExists(outside / "deep"),
    "unseal must not create directories through the symlink"
  removeDir(outside)
  removeDir(r)
  echo "PASS: unseal refuses a symlink ancestor"

block unsealDoesNotFollowAncestorSymlinkWithoutRoot:
  ## The no-root mode must reject the same ancestor symlink escape.
  let oldHome = getEnv("HOME")
  let base = createTempDir("nimvault_audit_", "_home")
  let home = base / "home"
  let outside = base / "outside"
  createDir(home)
  createDir(outside)
  let r = setupRepo()
  putEnv("HOME", home)
  try:
    let c = GpgConfig(recipient: keyId)
    createDir(home / "nested" / "deep")
    let f = home / "nested" / "deep" / "secret.txt"
    writeFile(f, "sym-secret-no-root")
    add(r, "~/nested/deep/secret.txt", c)
    seal(r, c)
    removeFile(f)
    removeDir(home / "nested" / "deep")
    removeDir(home / "nested")
    createSymlink(outside, home / "nested")
    var raised = false
    try:
      unseal(r, c, allowUnsigned = true)
    except CatchableError:
      raised = true
    doAssert raised, "unseal must refuse a HOME-relative symlink ancestor"
    doAssert not fileExists(outside / "deep" / "secret.txt"),
      "plaintext must not be written outside HOME through a symlink"
  finally:
    putEnv("HOME", oldHome)
    removeDir(r)
    removeDir(base)
  echo "PASS: unseal refuses a symlink ancestor without root"

block addRejectsTildePathWhoseRealPathLeavesHome:
  ## A ~/ spelling must not hide a canonical path outside HOME.
  let oldHome = getEnv("HOME")
  let base = createTempDir("nimvault_audit_", "_home")
  let home = base / "home"
  let outside = base / "outside"
  createDir(home)
  createDir(outside)
  let r = setupRepo()
  putEnv("HOME", home)
  try:
    let c = GpgConfig(recipient: keyId)
    let ext = outside / "outside.txt"
    writeFile(ext, "outside-secret")
    createSymlink(outside, home / "link")
    var raised = false
    try:
      add(r, "~/link/outside.txt", c)
    except CatchableError:
      raised = true
    doAssert raised, "add must refuse a ~/ path whose real path leaves HOME"
    doAssert loadManifest(r, cfg = c).len == 0
  finally:
    putEnv("HOME", oldHome)
    removeDir(r)
    removeDir(base)
  echo "PASS: add rejects a ~/ path that resolves outside HOME"

block unsealDoesNotCopyThroughFinalSymlink:
  ## Runtime dir and the vault are on different devices. moveFile then copies,
  ## and a copy follows a symlink planted at the destination.
  let shm = secondFs("nimvault-audit-")
  if shm.len == 0:
    echo "SKIP: cross-device unseal (no second filesystem)"
  else:
    let oldXdg = getEnv("XDG_RUNTIME_DIR")
    putEnv("XDG_RUNTIME_DIR", shm)
    let r = setupRepo()
    let c = GpgConfig(recipient: keyId, root: r)
    let f = r / "secret.txt"
    writeFile(f, "cross-device-secret")
    add(r, f, c)
    seal(r, c)
    removeFile(f)
    let leakDir = createTempDir("nimvault_audit_", "_leak")
    let leak = leakDir / "leak.txt"
    writeFile(leak, "do-not-touch")
    createSymlink(leak, f)
    unseal(r, c, allowUnsigned = true)
    doAssert readFile(leak) == "do-not-touch",
      "unseal must not write the secret through a destination symlink"
    doAssert not symlinkExists(f), "the vault path must be a regular file"
    doAssert readFile(f) == "cross-device-secret"
    if oldXdg.len > 0: putEnv("XDG_RUNTIME_DIR", oldXdg)
    else: delEnv("XDG_RUNTIME_DIR")
    removeDir(leakDir)
    removeDir(r)
    removeDir(shm)
    echo "PASS: unseal replaces a destination symlink instead of following it"

block mvRefusesFinalSymlink:
  ## mv must reject a destination symlink instead of replacing or following it.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let oldPath = r / "secret.txt"
  writeFile(oldPath, "move-me")
  add(r, oldPath, c)
  seal(r, c)
  let leakDir = createTempDir("nimvault_audit_", "_mvlink")
  let leak = leakDir / "leak.txt"
  writeFile(leak, "do-not-touch")
  let newPath = r / "renamed.txt"
  createSymlink(leak, newPath)
  var raised = false
  try:
    move(r, oldPath, newPath, c)
  except CatchableError:
    raised = true
  doAssert raised, "mv must refuse a destination symlink"
  doAssert readFile(leak) == "do-not-touch",
    "mv must not write through the destination symlink"
  doAssert fileExists(oldPath), "a refused mv must leave the source in place"
  removeDir(leakDir)
  removeDir(r)
  echo "PASS: mv refuses a destination symlink"

block mvDoesNotCopyThroughSymlinkAcrossFilesystems:
  ## The cross-filesystem fallback must not copy through a destination symlink.
  let shm = secondFs("nimvault-audit-mv-")
  if shm.len == 0:
    echo "SKIP: cross-device mv (no second filesystem)"
  else:
    let oldHome = getEnv("HOME")
    let base = createTempDir("nimvault_audit_", "_home")
    let home = base / "home"
    createDir(home)
    let r = setupRepo()
    putEnv("HOME", home)
    try:
      let c = GpgConfig(recipient: keyId)
      let src = home / "secret.txt"
      writeFile(src, "cross-device-move")
      add(r, "~/secret.txt", c)
      seal(r, c)
      let leakDir = createTempDir("nimvault_audit_", "_mvleak")
      let leak = leakDir / "leak.txt"
      writeFile(leak, "do-not-touch")
      let dst = shm / "moved-secret.txt"
      createSymlink(leak, dst)
      var raised = false
      try:
        move(r, src, dst, c)
      except CatchableError:
        raised = true
      doAssert raised, "mv must reject a destination symlink across filesystems"
      doAssert readFile(leak) == "do-not-touch",
        "mv must not copy plaintext through a destination symlink"
      doAssert fileExists(src), "a refused mv must keep the source file"
      removeDir(leakDir)
    finally:
      putEnv("HOME", oldHome)
      removeDir(r)
      removeDir(base)
      removeDir(shm)
    echo "PASS: cross-device mv does not copy through a destination symlink"

block mvAcrossFilesystemsKeepsTheSourceMode:
  ## The copy fallback created the new file with the process umask, so a
  ## 0600 secret arrived 0644.
  let shm = secondFs("nimvault-audit-mvmode-")
  if shm.len == 0:
    echo "SKIP: cross-device mv mode (no second filesystem)"
  else:
    let oldHome = getEnv("HOME")
    let base = createTempDir("nimvault_audit_", "_home")
    let home = base / "home"
    createDir(home)
    let r = setupRepo()
    putEnv("HOME", home)
    let oldMask = umask(0o022.Mode)
    try:
      let c = GpgConfig(recipient: keyId)
      for (name, perms) in [("secret.txt", {fpUserRead, fpUserWrite}),
                            ("hook.sh", {fpUserRead, fpUserWrite, fpUserExec})]:
        let src = home / name
        writeFile(src, "cross-device-" & name)
        setFilePermissions(src, perms)
        add(r, "~/" & name, c)
        seal(r, c)
        let dst = shm / name
        move(r, src, dst, c)
        doAssert not fileExists(src), "mv must remove the source"
        doAssert readFile(dst) == "cross-device-" & name
        doAssert getFilePermissions(dst) == perms,
          &"mv must keep the source mode for {name}: {getFilePermissions(dst)}"
        doAssert get(r, dst, c) == "cross-device-" & name
      for kind, path in walkDir(shm):
        doAssert ".nimvault-mv-" notin path, "mv must not leave its copy: " & path
    finally:
      discard umask(oldMask)
      putEnv("HOME", oldHome)
      removeDir(r)
      removeDir(base)
      removeDir(shm)
    echo "PASS: cross-device mv keeps the source mode"

block mvAcrossFilesystemsShredsTheSource:
  ## The copy fallback unlinked the source, which leaves its blocks intact for
  ## anything still holding the inode. A descriptor opened before the move sees
  ## whether the bytes were overwritten.
  let shm = secondFs("nimvault-audit-mvshred-")
  if shm.len == 0:
    echo "SKIP: cross-device mv shred (no second filesystem)"
  else:
    let oldHome = getEnv("HOME")
    let base = createTempDir("nimvault_audit_", "_home")
    let home = base / "home"
    createDir(home)
    let r = setupRepo()
    putEnv("HOME", home)
    try:
      let c = GpgConfig(recipient: keyId)
      let src = home / "secret.txt"
      let secret = "cross-device-shred-me"
      writeFile(src, secret)
      add(r, "~/secret.txt", c)
      seal(r, c)
      var held = open(src, fmRead)
      try:
        let dst = shm / "secret.txt"
        move(r, src, dst, c)
        doAssert not fileExists(src), "mv must remove the source"
        doAssert readFile(dst) == secret
        let left = held.readAll()
        doAssert left.len == secret.len, "shred keeps the length: " & $left.len
        doAssert left != secret,
          "mv across filesystems must overwrite the source before removing it"
      finally:
        held.close()
    finally:
      putEnv("HOME", oldHome)
      removeDir(r)
      removeDir(base)
      removeDir(shm)
    echo "PASS: cross-device mv shreds the source"

block mvRefusesSourceUnderSymlinkedAncestor:
  ## `rename` follows a directory symlink above the source. With the entry's
  ## directory swapped for a link out of the root, mv would pull the outside
  ## file into the vault's tree and remove it from where it was.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  createDir(r / "nested")
  let src = r / "nested" / "secret.txt"
  writeFile(src, "in-root")
  add(r, src, c)
  seal(r, c)
  removeFile(src)
  removeDir(r / "nested")
  let outside = createTempDir("nimvault_audit_", "_mvsrc")
  writeFile(outside / "secret.txt", "outside-bytes")
  createSymlink(outside, r / "nested")
  let dst = r / "moved.txt"
  var raised = false
  try:
    move(r, src, dst, c)
  except CatchableError:
    raised = true
  doAssert raised, "mv must refuse a source reached through a symlink out of the root"
  doAssert readFile(outside / "secret.txt") == "outside-bytes",
    "mv must leave the outside file where it is"
  doAssert not fileExists(dst), "mv must not place the outside file in the root"
  removeDir(outside)
  removeDir(r)
  echo "PASS: mv refuses a source under a symlinked ancestor"

block mvRefusesSourceUnderSymlinkedAncestorWithoutRoot:
  let oldHome = getEnv("HOME")
  let base = createTempDir("nimvault_audit_", "_home")
  let home = base / "home"
  let outside = base / "outside"
  createDir(home)
  createDir(outside)
  let r = setupRepo()
  putEnv("HOME", home)
  try:
    let c = GpgConfig(recipient: keyId)
    createDir(home / "nested")
    writeFile(home / "nested" / "secret.txt", "in-home")
    add(r, "~/nested/secret.txt", c)
    seal(r, c)
    removeFile(home / "nested" / "secret.txt")
    removeDir(home / "nested")
    writeFile(outside / "secret.txt", "outside-bytes")
    createSymlink(outside, home / "nested")
    var raised = false
    try:
      move(r, "~/nested/secret.txt", "~/moved.txt", c)
    except CatchableError:
      raised = true
    doAssert raised, "mv must refuse a source reached through a symlink out of HOME"
    doAssert readFile(outside / "secret.txt") == "outside-bytes",
      "mv must leave the file outside HOME where it is"
    doAssert not fileExists(home / "moved.txt")
  finally:
    putEnv("HOME", oldHome)
    removeDir(r)
    removeDir(base)
  echo "PASS: mv refuses a source under a symlinked ancestor without root"

block sealRefusesPlaintextUnderSymlinkedAncestor:
  ## seal reads the plaintext a record names. With the entry's directory
  ## swapped for a link out of the root, it encrypted the outside file into
  ## the blob and replaced the sealed copy. `rotate --rekey` seals too.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  createDir(r / "nested")
  let f = r / "nested" / "secret.txt"
  writeFile(f, "sealed-copy")
  add(r, f, c)
  seal(r, c)
  removeFile(f)
  removeDir(r / "nested")
  let outside = createTempDir("nimvault_audit_", "_sealsrc")
  writeFile(outside / "secret.txt", "outside-bytes")
  createSymlink(outside, r / "nested")
  for rekey in [false, true]:
    var raised = false
    try:
      if rekey: rotate(r, c, rekey = true)
      else: seal(r, c)
    except CatchableError:
      raised = true
    doAssert raised, "seal (rekey: " & $rekey &
      ") must refuse plaintext under a symlink out of the root"
    doAssert get(r, f, c) == "sealed-copy",
      "a refused seal must leave the sealed copy in place"
  removeFile(r / "nested")
  createDir(r / "nested")
  createSymlink(outside / "secret.txt", f)
  var raised = false
  try:
    seal(r, c)
  except CatchableError:
    raised = true
  doAssert raised, "seal must refuse a plaintext symlink that leaves the root"
  doAssert get(r, f, c) == "sealed-copy"
  removeDir(outside)
  removeDir(r)
  echo "PASS: seal and rotate --rekey refuse plaintext under a symlinked ancestor"

block rotateReadsUnderTheLock:
  ## rotate without --rekey must not read records before taking the lock.
  ## Otherwise a removal made while it waits is replayed when it force-writes.
  ## The lock is held by another process, as a concurrent command would.
  let r = setupRepo()
  createDir(r / ".vault")
  writeFile(r / ".vault" / "config", &"recipient = {keyId}\nroot = repo\n")
  let c = GpgConfig(recipient: keyId, root: r)
  for name in ["kept.txt", "removed.txt"]:
    writeFile(r / name, "rotate-lock-" & name)
    add(r, r / name, c)
  seal(r, c)
  var removed = ""
  for e in loadManifest(r, cfg = c):
    if e.path == "removed.txt":
      removed = entryFile(r, c, e.id)
  doAssert removed.len > 0
  var made = acquire(r)
  release(made)
  let holder = startProcess(findExe("python3"), args = @["-c", """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.lockf(fd, fcntl.LOCK_EX)
print("held", flush=True)
sys.stdin.readline()
""", lockPath(r)], options = {poStdErrToStdOut})
  doAssert holder.outputStream.readLine() == "held"
  let rotating = startProcess(cliExe(), workingDir = r, args = @["rotate"],
                              options = {poStdErrToStdOut})
  sleep(1500)
  doAssert rotating.running, "rotate must wait for the lock"
  removeFile(removed)
  holder.inputStream.writeLine("")
  holder.inputStream.close()
  doAssert holder.waitForExit() == 0
  holder.close()
  let outp = rotating.outputStream.readAll()
  let code = rotating.waitForExit()
  rotating.close()
  doAssert code == 0, "rotate must finish once the lock is free:\n" & outp
  let left = loadManifest(r, verifySig = true, cfg = c)
  doAssert left.len == 1 and left[0].path == "kept.txt",
    "rotate must read records under the lock and not resurrect a removed record"
  doAssert not fileExists(removed)
  removeDir(r)
  echo "PASS: rotate reads records under the lock"

proc payloadDecryptHook(realGpg: string): string =
  ## A gpg wrapper that runs $NIMVAULT_SWAP_CMD once, when gpg decrypts a
  ## payload blob. Records under `.vault/e/` and key files are decrypted while
  ## the records load, before the checks a swap has to come after.
  """#!/bin/sh
set -eu
last=""
for arg in "$@"; do last="$arg"; done
case " $* " in
  *" -d "*|*" --decrypt "*) decrypt=1 ;;
  *) decrypt="" ;;
esac
if [ -n "$decrypt" ] && [ -n "${NIMVAULT_SWAP_CMD:-}" ] &&
   [ ! -e "${NIMVAULT_SWAP_MARKER:-}" ]; then
  case "$last" in
    */.vault/e/*) ;;
    */.vault/[0-9a-f]*.gpg)
      sh -c "$NIMVAULT_SWAP_CMD"
      : >"$NIMVAULT_SWAP_MARKER"
      ;;
  esac
fi
exec """ & realGpg.quoteShell & """ "$@"
"""

block unsealUsesDescriptorAnchoredStaging:
  ## A parent swapped after path checks must now fail before placement.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let inside = r / "inside"
  let outside = createTempDir("nimvault_audit_", "_outside")
  createDir(inside)
  createSymlink(inside, r / "safe")
  let f = r / "safe" / "secret.txt"
  writeFile(f, "anchored-secret")
  add(r, f, c)
  seal(r, c)
  removeFile(inside / "secret.txt")

  let wrapBin = createTempDir("nimvault_audit_", "_gpgwrap")
  let marker = wrapBin / "swapped"
  let realGpg = findExe("gpg")
  doAssert realGpg.len > 0
  let wrapper = wrapBin / "gpg"
  let swapCmd = "rm -f " & (r / "safe").quoteShell &
                " && ln -s " & outside.quoteShell & " " & (r / "safe").quoteShell
  writeFile(wrapper, payloadDecryptHook(realGpg))
  setFilePermissions(wrapper, {fpUserRead, fpUserWrite, fpUserExec})
  let oldPath = getEnv("PATH")
  putEnv("PATH", wrapBin & ":" & oldPath)
  putEnv("NIMVAULT_SWAP_CMD", swapCmd)
  putEnv("NIMVAULT_SWAP_MARKER", marker)
  var raised = false
  try:
    try:
      unseal(r, c)
    except CatchableError:
      raised = true
  finally:
    putEnv("PATH", oldPath)
    delEnv("NIMVAULT_SWAP_CMD")
    delEnv("NIMVAULT_SWAP_MARKER")
  doAssert fileExists(marker), "test wrapper did not swap the parent symlink"
  doAssert raised, "unseal must refuse a parent changed after path checks"
  doAssert not fileExists(inside / "secret.txt"),
    "a refused unseal must not leave plaintext under the original parent"
  doAssert not fileExists(outside / "secret.txt"),
    "unseal must not be redirected outside the vault root"
  if symlinkExists(r / "safe"):
    removeFile(r / "safe")
  removeDir(r)
  removeDir(outside)
  removeDir(wrapBin)
  echo "PASS: unseal stages and renames under a stable directory descriptor"

proc stagingFiles(dir: string): seq[string] =
  for path in walkDirRec(dir, yieldFilter = {pcFile, pcLinkToFile}):
    if path.extractFilename.startsWith(".nimvault-"):
      result.add(path)

block unsealRefusedSwapLeavesNoStagingFile:
  ## Both entry directories are swapped for links out of the root while the
  ## first entry decrypts. The second is refused. The first entry's staging
  ## file sat in a directory that is now elsewhere, and a raise outside the
  ## cleanup left it there with the plaintext in it.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let outside = createTempDir("nimvault_audit_", "_outside")
  for d in ["a", "b"]:
    createDir(r / d)
    writeFile(r / d / "secret.txt", "swap-secret-" & d)
    add(r, r / d / "secret.txt", c)
  seal(r, c)
  for d in ["a", "b"]:
    removeFile(r / d / "secret.txt")
  let wrapBin = createTempDir("nimvault_audit_", "_gpgwrap")
  let wrapper = wrapBin / "gpg"
  writeFile(wrapper, payloadDecryptHook(findExe("gpg")))
  setFilePermissions(wrapper, {fpUserRead, fpUserWrite, fpUserExec})
  var swapCmd = ""
  for d in ["a", "b"]:
    let p = (r / d).quoteShell
    swapCmd.add(&"mv {p} {(r / (d & \".moved\")).quoteShell} && " &
                &"ln -s {outside.quoteShell} {p} && ")
  swapCmd.add("true")
  let oldPath = getEnv("PATH")
  putEnv("PATH", wrapBin & ":" & oldPath)
  putEnv("NIMVAULT_SWAP_CMD", swapCmd)
  putEnv("NIMVAULT_SWAP_MARKER", wrapBin / "swapped")
  var raised = false
  try:
    unseal(r, c)
  except CatchableError:
    raised = true
  finally:
    putEnv("PATH", oldPath)
    delEnv("NIMVAULT_SWAP_CMD")
    delEnv("NIMVAULT_SWAP_MARKER")
  doAssert fileExists(wrapBin / "swapped"), "test wrapper did not swap"
  doAssert raised, "unseal must refuse an entry whose directory now leaves the root"
  doAssert stagingFiles(r).len == 0,
    "a refused unseal must not leave staged plaintext: " & $stagingFiles(r)
  doAssert stagingFiles(outside).len == 0
  for kind, path in walkDir(outside):
    doAssert false, "unseal wrote outside the root: " & path
  removeDir(r)
  removeDir(outside)
  removeDir(wrapBin)
  echo "PASS: a refused swap leaves no staging file"

block unsealWithoutRootStaysInHomeAfterASwap:
  ## With no root the boundary is $HOME. Renaming an already-open parent
  ## directory outside $HOME during decrypt must not send plaintext there.
  let oldHome = getEnv("HOME")
  let base = createTempDir("nimvault_audit_", "_home")
  let home = base / "home"
  let outside = base / "outside"
  createDir(home)
  createDir(outside)
  let r = setupRepo()
  putEnv("HOME", home)
  let wrapBin = createTempDir("nimvault_audit_", "_gpgwrap")
  let oldPath = getEnv("PATH")
  var raised = false
  let moved = outside / "a.moved"
  try:
    let c = GpgConfig(recipient: keyId)
    createDir(home / "a")
    writeFile(home / "a" / "secret.txt", "home-secret-a")
    add(r, "~/a/secret.txt", c)
    seal(r, c)
    removeFile(home / "a" / "secret.txt")
    writeFile(wrapBin / "gpg", payloadDecryptHook(findExe("gpg")))
    setFilePermissions(wrapBin / "gpg", {fpUserRead, fpUserWrite, fpUserExec})
    let swapCmd = "mv " & (home / "a").quoteShell & " " & moved.quoteShell &
                  " && mkdir " & (home / "a").quoteShell
    putEnv("PATH", wrapBin & ":" & oldPath)
    putEnv("NIMVAULT_SWAP_CMD", swapCmd)
    putEnv("NIMVAULT_SWAP_MARKER", wrapBin / "swapped")
    try:
      unseal(r, c)
    except CatchableError:
      raised = true
  finally:
    putEnv("PATH", oldPath)
    delEnv("NIMVAULT_SWAP_CMD")
    delEnv("NIMVAULT_SWAP_MARKER")
    putEnv("HOME", oldHome)
  doAssert fileExists(wrapBin / "swapped"), "test wrapper did not swap"
  doAssert raised, "unseal must fail after a parent rename out of HOME"
  doAssert not fileExists(moved / "secret.txt"),
    "unseal must not write plaintext outside HOME through a renamed parent"
  doAssert not fileExists(home / "a" / "secret.txt"),
    "a refused unseal must not place plaintext under the replacement parent"
  doAssert stagingFiles(home).len == 0, $stagingFiles(home)
  doAssert stagingFiles(outside).len == 0, $stagingFiles(outside)
  removeDir(r)
  removeDir(base)
  removeDir(wrapBin)
  echo "PASS: unseal without root refuses a parent renamed out of HOME"

block directEntryIsStagedOnce:
  ## A direct v5 entry was staged twice, once with the v6 entries and once
  ## in its own batch, and the first file sat empty for the whole run.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let old = r / "old.txt"
  writeFile(old, "staged-once")
  createDir(r / ".vault")
  let id = "5b5b5b5b5b5b5b5b"
  let blob = crypto.blobPath(r, c, id)
  encryptFile(c, old, blob)
  saveManifest(r, @[(id, "old.txt", sha256sum(blob), ekFile, sha256sum(old))], c,
               sealKey(c))
  removeFile(old)
  let wrapBin = createTempDir("nimvault_audit_", "_gpgwrap")
  let log = wrapBin / "staged.log"
  writeFile(wrapBin / "gpg", """#!/bin/sh
last=""
for arg in "$@"; do last="$arg"; done
case "$last" in
  */.vault/e/*) ;;
  */.vault/[0-9a-f]*.gpg)
    ls -A """ & r.quoteShell & """ | grep -c '^\.nimvault-' >>""" & log.quoteShell & """ || true
    ;;
esac
exec """ & findExe("gpg").quoteShell & """ "$@"
""")
  setFilePermissions(wrapBin / "gpg", {fpUserRead, fpUserWrite, fpUserExec})
  let oldPath = getEnv("PATH")
  putEnv("PATH", wrapBin & ":" & oldPath)
  try:
    unseal(r, c)
  finally:
    putEnv("PATH", oldPath)
  doAssert readFile(old) == "staged-once"
  var counts: seq[string] = @[]
  for line in readFile(log).splitLines:
    if line.len > 0:
      counts.add(line)
  doAssert counts.len > 0, "the wrapper never saw the payload decrypt"
  for n in counts:
    doAssert parseInt(n) <= 1,
      "a direct entry must have one staging file at most: " & $counts
  doAssert stagingFiles(r).len == 0
  removeDir(r)
  removeDir(wrapBin)
  echo "PASS: a direct entry is staged once"

block sealRefusesPlaintextUnderSymlinkedAncestorWithoutRoot:
  let oldHome = getEnv("HOME")
  let base = createTempDir("nimvault_audit_", "_home")
  let home = base / "home"
  let outside = base / "outside"
  createDir(home)
  createDir(outside)
  let r = setupRepo()
  putEnv("HOME", home)
  try:
    let c = GpgConfig(recipient: keyId)
    createDir(home / "nested")
    writeFile(home / "nested" / "secret.txt", "sealed-copy")
    add(r, "~/nested/secret.txt", c)
    seal(r, c)
    removeFile(home / "nested" / "secret.txt")
    removeDir(home / "nested")
    writeFile(outside / "secret.txt", "outside-bytes")
    createSymlink(outside, home / "nested")
    var raised = false
    try:
      seal(r, c)
    except CatchableError:
      raised = true
    doAssert raised, "seal must refuse plaintext under a symlink out of HOME"
    doAssert get(r, "~/nested/secret.txt", c) == "sealed-copy"
  finally:
    putEnv("HOME", oldHome)
    removeDir(r)
    removeDir(base)
  echo "PASS: seal refuses plaintext under a symlinked ancestor without root"

block addRefusesSymlink:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let outside = createTempDir("nimvault_audit_", "_link")
  let ext = outside / "outside.txt"
  writeFile(ext, "not-for-the-vault")
  createSymlink(ext, r / "link.txt")
  var raised = false
  try:
    add(r, r / "link.txt", c)
  except CatchableError:
    raised = true
  doAssert raised, "add must refuse a symlink"
  doAssert loadManifest(r, cfg = c).len == 0
  removeDir(outside)
  removeDir(r)
  echo "PASS: add refuses a symlink"

block addRefusesManifestMetacharacters:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "a\tb.txt"
  writeFile(f, "tab-name")
  var raised = false
  try:
    add(r, f, c)
  except CatchableError:
    raised = true
  doAssert raised, "add must refuse a path the manifest cannot store"
  doAssert loadManifest(r, cfg = c).len == 0
  removeDir(r)
  echo "PASS: add refuses a tab in the path"

block sealFailureKeepsTheOldBlob:
  ## The live blob is the one the record names until the new record is durable.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "original-secret")
  add(r, f, c)
  seal(r, c)
  doAssert get(r, f, c, allowUnsigned = true) == "original-secret"
  writeFile(f, "edited-secret")
  let edir = entryDir(r)
  setFilePermissions(edir, {fpUserRead, fpUserExec})
  var raised = false
  try:
    seal(r, c)
  except CatchableError:
    raised = true
  setFilePermissions(edir, {fpUserRead, fpUserWrite, fpUserExec})
  doAssert raised, "seal must fail when the record directory is not writable"
  doAssert get(r, f, c, allowUnsigned = true) == "original-secret",
    "a failed seal must leave the previous blob decryptable"
  removeDir(r)
  echo "PASS: a failed seal does not destroy the previous blob"

block pendingBlobIsPromoted:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "promoted-secret")
  add(r, f, c)
  seal(r, c)
  let e = loadManifest(r, cfg = c)[0]
  let blob = findBlob(r, c, e.id)
  copyFile(blob, blob & ".pending")
  writeFile(blob, "corrupt")
  doAssert get(r, f, c, allowUnsigned = true) == "promoted-secret"
  doAssert sha256sum(blob) == e.hash, "the pending blob should be promoted"
  removeDir(r)
  echo "PASS: a pending blob that matches the record is promoted"

block gcKeepsReferencedPending:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "keep-pending")
  add(r, f, c)
  seal(r, c)
  let e = loadManifest(r, cfg = c)[0]
  let blob = findBlob(r, c, e.id)
  copyFile(blob, blob & ".pending")
  writeFile(blob, "corrupt-live")
  gc(r, c)
  doAssert fileExists(blob & ".pending"), "gc must keep a pending blob the record names"
  doAssert get(r, f, c, allowUnsigned = true) == "keep-pending"
  removeDir(r)
  echo "PASS: gc keeps a pending blob the record names"

block gcKeepsPendingNamedByTmpRecord:
  ## A pending blob can be live before its record rename: e/<id>.gpg.tmp names
  ## it during that window.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "tmp-record-pending")
  add(r, f, c)
  seal(r, c)
  let e = loadManifest(r, cfg = c)[0]
  let blob = findBlob(r, c, e.id)
  let pend = blob & ".pending"
  writeFile(pend, "new-ciphertext-not-yet-published")
  let recTmp = entryFile(r, c, e.id) & ".tmp"
  let recips = recipientsFor(c, e.path)
  let deks = loadDeks(r, c)
  doAssert deks.hasKey(e.id)
  let work = createTempDir("nimvault_audit_", "_tmprec")
  let plain = work / "record.plain"
  writeFile(plain, EntryHeader & "\n" &
    &"{e.id}\t{e.path}\t{sha256sum(pend)}\t{e.kind}\t{e.contentHash}\t" &
    deks[e.id] & "\n")
  encryptFileTo(c, recips, plain, recTmp, sign = true)
  gc(r, c)
  doAssert fileExists(pend),
    "gc must keep a pending blob named by an in-flight tmp record"
  removeDir(work)
  removeDir(r)
  echo "PASS: gc keeps pending blobs named by tmp records"

block gcDropsUnreferencedPending:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "drop-pending")
  add(r, f, c)
  seal(r, c)
  let e = loadManifest(r, cfg = c)[0]
  let blob = findBlob(r, c, e.id)
  let pend = blob & ".pending"
  writeFile(pend, "not-the-recorded-ciphertext")
  gc(r, c)
  doAssert not fileExists(pend), "gc must remove a pending blob the record does not name"
  doAssert get(r, f, c, allowUnsigned = true) == "drop-pending"
  removeDir(r)
  echo "PASS: gc removes an unreferenced pending blob"

block gcCleansLeftoversAndKeepsUnreadPending:
  ## A killed unseal leaves plaintext staged beside the destination, and a
  ## killed seal leaves a half-written pending blob. A pending blob whose
  ## record belongs to another machine's wrap group is not this machine's
  ## to judge.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  createDir(r / "sub")
  let f = r / "sub" / "secret.txt"
  writeFile(f, "gc-leftovers")
  add(r, f, c)
  seal(r, c)
  let e = loadManifest(r, cfg = c)[0]
  let staged = r / "sub" / ".nimvault-0123456789abcdef.tmp"
  writeFile(staged, "plaintext-left-by-a-killed-unseal")
  let pendTmp = crypto.blobPath(r, c, e.id) & ".pending.tmp"
  writeFile(pendTmp, "half-written-ciphertext")
  let foreign = "dddddddddddddddd"
  let savedHome = getEnv("GNUPGHOME")
  let foreignHome = gpgHome("foreign")
  putEnv("GNUPGHOME", foreignHome)
  let script = foreignHome / "keygen.txt"
  writeFile(script, """
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Foreign Machine
Name-Email: foreign-machine@nimvault.local
Expire-Date: 0
%commit
""")
  let (generated, gcode) = execCmdEx(&"gpg --batch --gen-key {script.quoteShell}")
  doAssert gcode == 0, generated
  let (listed, lcode) = execCmdEx(
    "gpg --list-keys --keyid-format long --with-colons foreign-machine@nimvault.local")
  doAssert lcode == 0, listed
  var foreignKey = ""
  for line in listed.splitLines:
    if line.startsWith("pub:"):
      let parts = line.split(':')
      if parts.len > 4:
        foreignKey = parts[4]
  doAssert foreignKey.len > 0
  let (pub, pcode) = execCmdEx("gpg --batch --export --armor " & foreignKey.quoteShell)
  doAssert pcode == 0, pub
  putEnv("GNUPGHOME", savedHome)
  let pubPath = foreignHome / "foreign.pub.asc"
  writeFile(pubPath, pub)
  let (imported, icode) = execCmdEx("gpg --batch --import " & pubPath.quoteShell)
  doAssert icode == 0, imported
  let recWork = createTempDir("nimvault_audit_", "_foreignrec")
  let recPlain = recWork / "record.plain"
  let foreignPend = crypto.blobPath(r, c, foreign) & ".pending"
  writeFile(foreignPend, "their-ciphertext")
  writeFile(recPlain, EntryHeader & "\n" &
    &"{foreign}\tforeign.txt\t{sha256sum(foreignPend)}\tfile\t{sha256sumBytes(foreign)}\t" &
    repeat('0', 64) & "\n")
  encryptFileTo(c, @[foreignKey], recPlain, entryFile(r, c, foreign), sign = true)
  removeDir(recWork)
  gc(r, c, dryRun = true)
  doAssert fileExists(staged) and fileExists(pendTmp) and fileExists(foreignPend),
    "a dry run removes nothing"
  gc(r, c)
  doAssert not fileExists(staged), "gc must shred plaintext an unseal staged"
  doAssert not fileExists(pendTmp), "gc must remove a half-written pending blob"
  doAssert fileExists(foreignPend),
    "gc must keep a pending blob whose record this machine cannot open"
  doAssert get(r, f, c, allowUnsigned = true) == "gc-leftovers"
  removeDir(foreignHome)
  removeDir(r)
  echo "PASS: gc cleans staging leftovers and keeps unread pending blobs"

block recordDekWinsOverKeyFile:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "dek-secret")
  add(r, f, c)
  seal(r, c)
  let id = loadManifest(r, cfg = c)[0].id
  let good = loadDeks(r, c)[id]
  for path in keyFiles(r, c):
    removeFile(path)
  let work = createTempDir("nimvault_audit_", "_keys")
  let plain = work / "keys.plain"
  writeFile(plain, "# vault-keys-v6\n" & id & "\t" & repeat('a', 64) & "\n")
  encryptFileTo(c, @[keyId], plain, r / ".vault" / "keys.evil.gpg", sign = false)
  doAssert loadDeks(r, c)[id] == good,
    "an unsigned key file must not override the data key in the record"
  doAssert get(r, f, c, allowUnsigned = true) == "dek-secret"
  removeDir(work)
  removeDir(r)
  echo "PASS: the signed record's data key wins over a key file"

block gitignoreLineIsLiteral:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let hashName = r / "#token"
  writeFile(hashName, "hunter2")
  createDir(r / "sub")
  writeFile(r / "sub" / "*.env", "star-secret")
  writeFile(r / "sub" / "a.env", "other")
  add(r, hashName, c)
  add(r, r / "sub" / "*.env", c)
  doAssert gitCode(r, @["check-ignore", "-q", "--", "#token"]) == 0,
    "#token must be gitignored (a leading hash is a comment)"
  doAssert gitCode(r, @["check-ignore", "-q", "--", "sub/*.env"]) == 0
  doAssert gitCode(r, @["check-ignore", "-q", "--", "sub/a.env"]) != 0,
    "ignoring one file must not ignore every file the glob would match"
  removeDir(r)
  echo "PASS: gitignore lines match the path literally"

block gpgOperandDashDash:
  ## An input path that looks like a flag must not become a flag. gpg --help
  ## exits 0, which would look like a successful encrypt.
  let cwd = getCurrentDir()
  let tmp = createTempDir("nimvault_audit_", "_gpgop")
  try:
    setCurrentDir(tmp)
    writeFile("--version", "operand-secret")
    let cfg = GpgConfig(recipient: keyId)
    let outp = tmp / "out.gpg"
    gpgEncrypt(cfg, "--version", outp)
    let back = tmp / "back.txt"
    gpgDecrypt(cfg, outp, back, verifySig = true)
    doAssert readFile(back) == "operand-secret"
  finally:
    setCurrentDir(cwd)
    removeDir(tmp)
  echo "PASS: gpg encrypt treats a flag-shaped path as a path"

block runtimeDirIsOwnerOnlyEvenIfPrecreated:
  let oldXdg = getEnv("XDG_RUNTIME_DIR")
  delEnv("XDG_RUNTIME_DIR")
  let parent = getTempDir() / ("nimvault-" & $getuid())
  var parked = ""
  if symlinkExists(parent):
    removeFile(parent)
  elif dirExists(parent):
    parked = parent & ".parked"
    moveDir(parent, parked)
  createDir(parent)
  setFilePermissions(parent, {fpUserRead, fpUserWrite, fpUserExec,
    fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  let work = privateWorkDir()
  let perms = getFilePermissions(parent)
  doAssert fpGroupRead notin perms and fpOthersRead notin perms and
    fpGroupExec notin perms and fpOthersExec notin perms,
    "runtime directory must be mode 0700"
  removeDir(work)
  removeDir(parent)
  if parked.len > 0 and dirExists(parked):
    moveDir(parked, parent)
  if oldXdg.len > 0: putEnv("XDG_RUNTIME_DIR", oldXdg)
  echo "PASS: a precreated runtime directory is tightened to 0700"

block runtimeDirRejectsSymlink:
  let oldXdg = getEnv("XDG_RUNTIME_DIR")
  delEnv("XDG_RUNTIME_DIR")
  let parent = getTempDir() / ("nimvault-" & $getuid())
  var parked = ""
  if symlinkExists(parent):
    removeFile(parent)
  elif dirExists(parent):
    parked = parent & ".parked2"
    if dirExists(parked): removeDir(parked)
    moveDir(parent, parked)
  createSymlink(getTempDir(), parent)
  var raised = false
  try:
    discard privateWorkDir()
  except CatchableError:
    raised = true
  doAssert raised, "runtime directory must not be a symlink"
  if symlinkExists(parent): removeFile(parent)
  if parked.len > 0 and dirExists(parked):
    moveDir(parked, parent)
  if oldXdg.len > 0: putEnv("XDG_RUNTIME_DIR", oldXdg)
  echo "PASS: a symlinked runtime directory is refused"

block scanSeesSecretsUnderTmp:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  createDir(r / "tmp")
  writeFile(r / "tmp" / "k.txt", "sk-ant-" & repeat('B', 30))
  var raised = false
  try:
    scan(r, r, c)
  except CatchableError as e:
    raised = true
    doAssert "sk-ant-" notin e.msg
    doAssert "tmp" in e.msg
  doAssert raised, "scan must not skip a repository directory named tmp"
  removeDir(r)
  echo "PASS: scan reports a secret under tmp/"

block scanCachedSeesStagedSecret:
  ## The worktree copy can be clean while the index still holds the secret,
  ## and a vaulted path is skipped by the worktree walk.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let notes = r / "notes.txt"
  writeFile(notes, "sk-ant-" & repeat('D', 30))
  doAssert gitCode(r, @["add", "--", "notes.txt"]) == 0
  writeFile(notes, "clean-worktree")
  scan(r, r, c)
  var raised = false
  try:
    scanCached(r, c, r)
  except CatchableError as e:
    raised = true
    doAssert "sk-ant-" notin e.msg
    doAssert "notes.txt" in e.msg
  doAssert raised, "scan --cached must see the index, not the worktree"
  # Clear the staged secret so the next check isolates vaulted-path handling.
  doAssert gitCode(r, @["add", "--", "notes.txt"]) == 0
  let vaulted = r / "secret.txt"
  writeFile(vaulted, "hunter2")
  add(r, vaulted, c)
  seal(r, c)
  doAssert gitCode(r, @["add", "-f", "--", "secret.txt"]) == 0
  raised = false
  try:
    scanCached(r, c, r)
  except CatchableError as e:
    raised = true
    doAssert "hunter2" notin e.msg
    doAssert "secret.txt" in e.msg
  doAssert raised, "a vaulted path forced into the index must be reported"
  removeDir(r)
  echo "PASS: scan --cached sees a staged secret the worktree walk misses"

block scanRevSeesSecretRemovedLater:
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let (baseRaw, bcode) = execCmdEx("git rev-parse HEAD", workingDir = r)
  doAssert bcode == 0, baseRaw
  let base = baseRaw.strip()
  let leak = r / "leak.txt"
  writeFile(leak, "sk-ant-" & repeat('C', 30))
  doAssert gitCode(r, @["add", "--", "leak.txt"]) == 0
  doAssert gitCode(r, @["commit", "-q", "-m", "add leak"]) == 0
  doAssert gitCode(r, @["rm", "-q", "--", "leak.txt"]) == 0
  doAssert gitCode(r, @["commit", "-q", "-m", "drop leak"]) == 0
  scan(r, r, c)
  let (headRaw, hcode) = execCmdEx("git rev-parse HEAD", workingDir = r)
  doAssert hcode == 0, headRaw
  var raised = false
  try:
    scanRev(r, c, r, base & ".." & headRaw.strip())
  except CatchableError as e:
    raised = true
    doAssert "sk-ant-" notin e.msg
    doAssert "leak.txt" in e.msg
  doAssert raised, "scan --rev must see a secret added and then removed"
  var bad = false
  try:
    scanRev(r, c, r, "--all")
  except CatchableError:
    bad = true
  doAssert bad, "scan --rev must refuse a revision that is not a sha range"
  removeDir(r)
  echo "PASS: scan --rev sees a secret that the tip no longer has"

block scanGitSeesOddNames:
  ## git hands these names over NUL-separated and they reach git again as
  ## `<rev>:<name>`, so neither a leading dash nor a newline is an option.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  for name in ["-leak.txt", "new\nline.txt"]:
    let (baseRaw, bcode) = execCmdEx("git rev-parse HEAD", workingDir = r)
    doAssert bcode == 0, baseRaw
    writeFile(r / name, "sk-ant-" & repeat('E', 30))
    doAssert gitCode(r, @["add", "--", name]) == 0
    var raised = false
    try:
      scanCached(r, c, r)
    except CatchableError as e:
      raised = true
      doAssert "sk-ant-" notin e.msg
    doAssert raised, "scan --cached must see a staged " & name.escape
    doAssert gitCode(r, @["commit", "-q", "-m", "odd name"]) == 0
    let (headRaw, hcode) = execCmdEx("git rev-parse HEAD", workingDir = r)
    doAssert hcode == 0, headRaw
    raised = false
    try:
      scanRev(r, c, r, baseRaw.strip() & ".." & headRaw.strip())
    except CatchableError:
      raised = true
    doAssert raised, "scan --rev must see a committed " & name.escape
    doAssert gitCode(r, @["rm", "-q", "--", name]) == 0
    doAssert gitCode(r, @["commit", "-q", "-m", "drop odd name"]) == 0
  removeDir(r)
  echo "PASS: scan --cached and --rev see names with a dash or a newline"

block hookScansIndexAndPushedCommits:
  let r = setupRepo()
  installHooks(r)
  let pre = readFile(r / ".git" / "hooks" / "pre-commit")
  let push = readFile(r / ".git" / "hooks" / "pre-push")
  doAssert "nimvault scan --cached" in pre
  doAssert "nimvault scan --rev" in push
  doAssert "--remote=" in push
  doAssert "nimvault check" in push
  removeDir(r)
  echo "PASS: hooks scan the index and the pushed commits"

const nimExe = getCurrentCompilerExe()
const srcRoot = currentSourcePath().parentDir.parentDir

proc buildCli(): string =
  ## The hooks call `nimvault` from PATH, so the test builds the one it runs.
  result = createTempDir("nimvault_audit_", "_bin")
  let (output, code) = execCmdEx(nimExe.quoteShell & " c --hints:off " &
    "--verbosity:0 -p:" & (srcRoot / "src").quoteShell & " -o:" &
    (result / "nimvault").quoteShell & " " &
    (srcRoot / "src" / "nimvault.nim").quoteShell)
  doAssert code == 0, output

proc runPrePush(repo, binDir, lines: string,
                args: seq[string]): tuple[outp: string, code: int] =
  let oldPath = getEnv("PATH")
  putEnv("PATH", binDir & ":" & oldPath)
  putEnv("NIMVAULT_GPG_RECIPIENT", keyId)
  try:
    let p = startProcess(repo / ".git" / "hooks" / "pre-push", workingDir = repo,
                         args = args, options = {poStdErrToStdOut})
    p.inputStream.write(lines)
    p.inputStream.close()
    result.outp = p.outputStream.readAll()
    result.code = p.waitForExit()
    p.close()
  finally:
    putEnv("PATH", oldPath)
    delEnv("NIMVAULT_GPG_RECIPIENT")

block prePushScansOnlyCommitsNewToTheRemote:
  ## A new branch used to scan its whole history, so a secret that was
  ## pushed and removed long ago blocked every new branch. A remote sha
  ## this clone lacks made rev-list fail with no hint.
  let binDir = buildCli()
  let remote = createTempDir("nimvault_audit_", "_remote")
  doAssert gitCode(remote, @["init", "-q", "--bare"]) == 0
  let r = setupRepo()
  let zero = repeat('0', 40)
  proc head(): string =
    let (raw, code) = execCmdEx("git rev-parse HEAD", workingDir = r)
    doAssert code == 0, raw
    raw.strip()
  doAssert gitCode(r, @["remote", "add", "origin", remote]) == 0
  writeFile(r / "leak.txt", "sk-ant-" & repeat('F', 30))
  doAssert gitCode(r, @["add", "--", "leak.txt"]) == 0
  doAssert gitCode(r, @["commit", "-q", "-m", "old leak"]) == 0
  doAssert gitCode(r, @["rm", "-q", "--", "leak.txt"]) == 0
  doAssert gitCode(r, @["commit", "-q", "-m", "drop old leak"]) == 0
  doAssert gitCode(r, @["push", "-q", "origin", "HEAD:refs/heads/main"]) == 0
  installHooks(r)

  doAssert gitCode(r, @["checkout", "-q", "-b", "feature"]) == 0
  writeFile(r / "clean.txt", "nothing secret")
  doAssert gitCode(r, @["add", "--", "clean.txt"]) == 0
  doAssert gitCode(r, @["commit", "-q", "--no-verify", "-m", "clean"]) == 0
  var got = runPrePush(r, binDir,
    &"refs/heads/feature {head()} refs/heads/feature {zero}\n", @["origin", remote])
  doAssert got.code == 0,
    "a new branch must not be blocked by history the remote already has:\n" & got.outp

  writeFile(r / "fresh.txt", "sk-ant-" & repeat('G', 30))
  doAssert gitCode(r, @["add", "--", "fresh.txt"]) == 0
  doAssert gitCode(r, @["commit", "-q", "--no-verify", "-m", "fresh leak"]) == 0
  got = runPrePush(r, binDir,
    &"refs/heads/feature {head()} refs/heads/feature {zero}\n", @["origin", remote])
  doAssert got.code != 0, "a new commit with a secret must block the push"
  doAssert "fresh.txt" in got.outp and "leak.txt" notin got.outp, got.outp

  got = runPrePush(r, binDir,
    &"refs/heads/feature {head()} refs/heads/main {repeat('e', 40)}\n",
    @["origin", remote])
  doAssert got.code != 0, "an unknown remote commit must block the push"
  doAssert "git fetch" in got.outp,
    "an unknown remote commit must say how to fix it:\n" & got.outp
  removeDir(r)
  removeDir(remote)
  removeDir(binDir)
  echo "PASS: pre-push scans only commits new to the remote"

var sharedCliDir = ""

proc cliExe(): string =
  ## The blocks below that run the command line share one build.
  if sharedCliDir.len == 0:
    sharedCliDir = buildCli()
  sharedCliDir / "nimvault"

proc runCli(dir: string, args: seq[string]): tuple[outp: string, code: int] =
  let p = startProcess(cliExe(), workingDir = dir, args = args,
                       options = {poStdErrToStdOut})
  result.outp = p.outputStream.readAll()
  result.code = p.waitForExit()
  p.close()

proc headOf(repo: string): string =
  let (raw, code) = execCmdEx("git rev-parse HEAD", workingDir = repo)
  doAssert code == 0, raw
  raw.strip()

block vaultedPlaintextFailsTheCommitAndPushScans:
  ## The pre-commit hook runs `scan --cached` and the pre-push hook runs
  ## `scan --rev`. A vaulted file in the index or in a commit is its plaintext
  ## entering git history, so both must fail on it, and still name the
  ## pattern its bytes match.
  let r = setupRepo()
  createDir(r / ".vault")
  writeFile(r / ".vault" / "config", &"recipient = {keyId}\nroot = repo\n")
  let token = "sk-ant-" & repeat('H', 30)
  writeFile(r / "token.txt", token)
  var got = runCli(r, @["add", "token.txt"])
  doAssert got.code == 0, got.outp
  got = runCli(r, @["seal"])
  doAssert got.code == 0, got.outp
  doAssert gitCode(r, @["add", "-A"]) == 0
  doAssert gitCode(r, @["commit", "-q", "--no-verify", "-m", "vault"]) == 0
  let base = headOf(r)

  doAssert gitCode(r, @["add", "-f", "--", "token.txt"]) == 0
  got = runCli(r, @["scan", "--cached"])
  doAssert got.code == 1, "a force-added vaulted file must fail scan --cached:\n" & got.outp
  doAssert "vault-plaintext" in got.outp and "token.txt" in got.outp, got.outp
  doAssert "anthropic-api-key" in got.outp,
    "a vaulted blob in the index must still be matched against the patterns:\n" & got.outp
  doAssert token notin got.outp, got.outp
  doAssert gitCode(r, @["reset", "-q", "--", "token.txt"]) == 0

  writeFile(r / "notes.txt", "hunter2")
  got = runCli(r, @["add", "--no-gitignore", "notes.txt"])
  doAssert got.code == 0, got.outp
  doAssert gitCode(r, @["add", "-A"]) == 0
  got = runCli(r, @["scan", "--cached"])
  doAssert got.code == 1,
    "add --no-gitignore then git add -A must fail scan --cached:\n" & got.outp
  doAssert "vault-plaintext" in got.outp and "notes.txt" in got.outp, got.outp
  doAssert "hunter2" notin got.outp, got.outp

  doAssert gitCode(r, @["commit", "-q", "--no-verify", "-m", "leak"]) == 0
  let tip = headOf(r)
  for rev in [tip, base & ".." & tip]:
    got = runCli(r, @["scan", "--rev", rev])
    doAssert got.code == 1,
      &"scan --rev {rev} must fail on a commit holding vaulted plaintext:\n" & got.outp
    doAssert "vault-plaintext" in got.outp and "notes.txt" in got.outp, got.outp
  removeDir(r)
  echo "PASS: scan --cached and --rev fail on vaulted plaintext"

block vaultedMatchIsByAbsolutePath:
  ## A record stores `notes/a.txt` relative to its root. The same relative
  ## name in another repository is a different file and must still be scanned.
  let v = setupRepo()
  let g = setupRepo()
  let c = GpgConfig(recipient: keyId, root: v)
  createDir(v / "notes")
  writeFile(v / "notes" / "a.txt", "vaulted-here")
  add(v, v / "notes" / "a.txt", c)
  seal(v, c)
  createDir(g / "notes")
  writeFile(g / "notes" / "a.txt", "sk-ant-" & repeat('K', 30))
  doAssert gitCode(g, @["add", "--", "notes/a.txt"]) == 0
  var raised = false
  try:
    scanCached(v, c, g)
  except CatchableError:
    raised = true
  doAssert raised,
    "a same-named file in another repository must not be skipped as vaulted"
  removeDir(v)
  removeDir(g)
  echo "PASS: vaulted matching is by absolute path"

block unsignedRecordDoesNotHideAFileFromScan:
  ## The worktree walk skips vaulted paths. An unsigned record, which anyone
  ## with the public key can write, must not choose what it skips.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  writeFile(r / "leak.txt", "sk-ant-" & repeat('J', 30))
  forgeUnsignedRecord(r, c, "abababababababab", "leak.txt")
  var raised = false
  try:
    scan(r, r, c)
  except CatchableError:
    raised = true
  doAssert raised, "an unsigned record must not hide a file from scan"
  doAssert gitCode(r, @["add", "--", "leak.txt"]) == 0
  raised = false
  try:
    scanCached(r, c, r)
  except CatchableError:
    raised = true
  doAssert raised, "an unsigned record must not hide a staged file from scan --cached"
  removeDir(r)
  echo "PASS: an unsigned record does not hide a file from scan"

block unsealWorksWithoutProc:
  ## Staging handed gpg a /proc/self/fd/<dirfd>/<name> path. macOS has no
  ## /proc, and a Linux container may not mount it. Hide it with a tmpfs in a
  ## user namespace where the kernel allows one.
  let probe = execCmdEx("unshare -rm sh -c " &
    "'mount -t tmpfs none /proc && test ! -e /proc/self'")
  if probe.exitCode != 0:
    echo "SKIP: unseal without /proc (no unprivileged user namespace)"
  else:
    let r = setupRepo()
    createDir(r / ".vault")
    writeFile(r / ".vault" / "config", &"recipient = {keyId}\nroot = repo\n")
    createDir(r / "sub")
    writeFile(r / "sub" / "a.txt", "no-proc-alpha")
    writeFile(r / "run.sh", "#!/bin/sh\necho no-proc\n")
    for f in ["sub/a.txt", "run.sh"]:
      let got = runCli(r, @["add", f])
      doAssert got.code == 0, got.outp
    let sealed = runCli(r, @["seal"])
    doAssert sealed.code == 0, sealed.outp
    removeDir(r / "sub")
    removeFile(r / "run.sh")
    let p = startProcess("unshare", workingDir = r,
      args = @["-rm", "sh", "-c",
               "mount -t tmpfs none /proc && exec " & cliExe().quoteShell & " unseal"],
      options = {poUsePath, poStdErrToStdOut})
    let outp = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    doAssert code == 0, "unseal must not need /proc:\n" & outp
    doAssert readFile(r / "sub" / "a.txt") == "no-proc-alpha"
    doAssert readFile(r / "run.sh") == "#!/bin/sh\necho no-proc\n"
    doAssert getFilePermissions(r / "run.sh") ==
      {fpUserRead, fpUserWrite, fpUserExec}
    doAssert getFilePermissions(r / "sub" / "a.txt") == {fpUserRead, fpUserWrite}
    removeDir(r)
    echo "PASS: unseal works with /proc hidden"

block unsealUnderALowDescriptorLimit:
  ## Every staged entry kept its directory open until the end of the run,
  ## so a vault larger than the descriptor limit could not be unsealed.
  let r = setupRepo()
  createDir(r / ".vault")
  writeFile(r / ".vault" / "config", &"recipient = {keyId}\nroot = repo\n")
  let c = GpgConfig(recipient: keyId, root: r)
  let tree = r / "tree"
  for i in 0 ..< 80:
    createDir(tree / &"d{i:02}")
    writeFile(tree / &"d{i:02}" / "f.txt", &"fd-limit-{i}")
  addDir(r, tree, c)
  seal(r, c)
  removeDir(tree)
  let p = startProcess("/bin/sh", workingDir = r,
    args = @["-c", "ulimit -n 64 && exec " & cliExe().quoteShell & " unseal"],
    options = {poStdErrToStdOut})
  let outp = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  doAssert code == 0, "unseal must restore 80 entries under ulimit -n 64:\n" & outp
  for i in 0 ..< 80:
    doAssert readFile(tree / &"d{i:02}" / "f.txt") == &"fd-limit-{i}"
  doAssert stagingFiles(r).len == 0, $stagingFiles(r)
  removeDir(r)
  echo "PASS: unseal restores 80 entries under ulimit -n 64"

block corruptRecordFailsCheckAndUnseal:
  ## A record this machine should be able to decrypt must not be skipped when
  ## corrupted.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let a = r / "a.txt"
  let b = r / "b.txt"
  writeFile(a, "alpha")
  writeFile(b, "beta")
  add(r, a, c)
  add(r, b, c)
  seal(r, c)
  var bId = ""
  for e in loadManifest(r, cfg = c):
    if resolvePath(c, e.path) == b:
      bId = e.id
  doAssert bId.len > 0
  writeFile(entryFile(r, c, bId), "corrupt-record-bytes")
  var raised = false
  try:
    discard checkReport(r, c)
  except CatchableError:
    raised = true
  doAssert raised, "check must fail loudly on a corrupt decryptable record"
  removeFile(a)
  removeFile(b)
  raised = false
  try:
    unseal(r, c)
  except CatchableError:
    raised = true
  doAssert raised, "unseal must fail loudly on a corrupt decryptable record"
  doAssert not fileExists(a) and not fileExists(b),
    "unseal must not restore partial plaintext when a record is corrupt"
  removeDir(r)
  echo "PASS: corrupt decryptable records fail check and unseal"

block checkWithoutSecretKey:
  ## The blob digests are inside the encrypted records. A public key can
  ## verify a signature; it cannot read those digests.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "check-needs-the-secret")
  add(r, f, c)
  seal(r, c)
  doAssert checkVault(r, c).problems.len == 0
  let home = getEnv("GNUPGHOME")
  let (exported, ecode) = execCmdEx("gpg --batch --export --armor " &
                                    keyId.quoteShell)
  doAssert ecode == 0, exported
  doAssert "BEGIN PGP PUBLIC KEY BLOCK" in exported
  doAssert "PRIVATE KEY" notin exported
  let pubHome = gpgHome("pub")
  writeFile(pubHome / "pub.asc", exported)
  try:
    putEnv("GNUPGHOME", pubHome)
    let (imported, icode) = execCmdEx(
      "gpg --batch --import " & (pubHome / "pub.asc").quoteShell)
    doAssert icode == 0, imported
    let (pubs, pcode) = execCmdEx("gpg --list-keys --with-colons")
    doAssert pcode == 0 and "pub:" in pubs, pubs
    let (secs, _) = execCmdEx("gpg --list-secret-keys --with-colons")
    doAssert "sec:" notin secs and "ssb:" notin secs, secs
    let looked = checkVault(r, c)
    doAssert looked.problems == @[
      "no records this identity can open; unread wrap groups remain"],
      "check without a secret key returned: " & $looked.problems
    var raised = false
    try:
      check(r, c)
    except CatchableError as e:
      raised = true
      doAssert "check-needs-the-secret" notin e.msg
      doAssert "entries consistent with the manifest" notin e.msg
      doAssert "restore the missing blob" notin e.msg,
        "a vault this key cannot open has no missing blob to restore: " & e.msg
      doAssert "secret key" in e.msg,
        "check must say the records need the secret key: " & e.msg
    doAssert raised, "check must not succeed without the secret key"
  finally:
    putEnv("GNUPGHOME", home)
    removeDir(pubHome)
  removeDir(r)
  echo "PASS: check cannot read the digests without the secret key"

block checkReportsUnreadRecords:
  ## A record this machine cannot open with any secret key is skippable, but
  ## check must say that it was skipped.
  let savedHome = getEnv("GNUPGHOME")
  let foreignHome = gpgHome("foreign")
  putEnv("GNUPGHOME", foreignHome)
  let foreignKey = genKey(foreignHome, "Foreign Box", "foreign@nimvault.local")
  let (exported, ecode) = execCmdEx("gpg --batch --export --armor " &
                                    foreignKey.quoteShell)
  doAssert ecode == 0, exported
  putEnv("GNUPGHOME", savedHome)
  let pub = createTempDir("nimvault_audit_", "_pub")
  writeFile(pub / "foreign.asc", exported)
  let (imported, icode) = execCmdEx("gpg --batch --import " &
                                    (pub / "foreign.asc").quoteShell)
  doAssert icode == 0, imported
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r, wraps: @[&"**/remote.txt:{foreignKey}"])
  let local = r / "local.txt"
  let remote = r / "remote.txt"
  writeFile(local, "local-secret")
  writeFile(remote, "remote-secret")
  add(r, local, c)
  add(r, remote, c)
  seal(r, c)
  let rep = checkReport(r, c)
  doAssert "could not open 1 record" in rep, rep
  var raised = false
  try:
    check(r, c)
  except CatchableError:
    raised = true
  doAssert not raised, "check should pass when unread records are genuine NO_SECKEY"
  removeDir(r)
  removeDir(pub)
  removeDir(foreignHome)
  putEnv("GNUPGHOME", savedHome)
  echo "PASS: check reports unread NO_SECKEY records"

block corruptSessionKeyForAHeldKeyFails:
  ## gpg reports NO_SECKEY for a session-key packet that names a key it holds
  ## but cannot open. One flipped byte made such a record read as not for this
  ## machine: check passed and unseal restored the rest without it.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  writeFile(r / "kept.txt", "kept-secret")
  writeFile(r / "hit.txt", "hit-secret")
  add(r, r / "kept.txt", c)
  add(r, r / "hit.txt", c)
  seal(r, c)
  var hitId = ""
  for e in loadManifest(r, verifySig = true, cfg = c):
    if e.path == "hit.txt":
      hitId = e.id
  doAssert hitId.len > 0
  let rec = findEntryFile(r, c, hitId)
  var bytes = readFile(rec)
  let ctb = ord(bytes[0])
  doAssert (ctb and 0xC0) == 0x80 and ((ctb shr 2) and 0xF) == 1,
    "the record does not open with a session-key packet"
  bytes[100] = char(ord(bytes[100]) xor 1)
  writeFile(rec, bytes)
  let (gpgStatus, _) = execCmdEx("gpg --batch --quiet --status-fd 1 -o /dev/null -d " &
                                 rec.quoteShell & " 2>/dev/null")
  doAssert "[GNUPG:] NO_SECKEY" in gpgStatus, gpgStatus
  doAssert "pkdecrypt_failed" in gpgStatus, gpgStatus
  var msg = ""
  try:
    check(r, c)
  except CatchableError as e:
    msg = e.msg
  doAssert "decrypt failed" in msg, "check passed over a corrupted record: " & msg
  removeFile(r / "kept.txt")
  removeFile(r / "hit.txt")
  msg = ""
  try:
    unseal(r, c)
  except CatchableError as e:
    msg = e.msg
  doAssert "decrypt failed" in msg, "unseal skipped a corrupted record: " & msg
  doAssert not fileExists(r / "kept.txt") and not fileExists(r / "hit.txt")
  removeDir(r)
  echo "PASS: a corrupted session key for a held key fails check and unseal"

block unsealReportsRecordsItCouldNotOpen:
  ## unseal restored what this machine could open and said nothing of the
  ## rest. With none it could open, it reported an empty vault.
  let savedHome = getEnv("GNUPGHOME")
  let foreignHome = gpgHome("foreign")
  putEnv("GNUPGHOME", foreignHome)
  let foreignKey = genKey(foreignHome, "Foreign Box", "foreign@nimvault.local")
  let (exported, ecode) = execCmdEx("gpg --batch --export --armor " &
                                    foreignKey.quoteShell)
  doAssert ecode == 0, exported
  putEnv("GNUPGHOME", savedHome)
  let pub = createTempDir("nimvault_audit_", "_pub")
  writeFile(pub / "foreign.asc", exported)
  let (imported, icode) = execCmdEx("gpg --batch --import " &
                                    (pub / "foreign.asc").quoteShell)
  doAssert icode == 0, imported
  let r = setupRepo()
  createDir(r / ".vault")
  writeFile(r / ".vault" / "config", &"recipient = {keyId}\nroot = repo\n" &
                                     &"wrap = **/remote.txt:{foreignKey}\n")
  let c = initGpgConfig("", r)
  let local = r / "local.txt"
  let remote = r / "remote.txt"
  writeFile(local, "local-secret")
  writeFile(remote, "remote-secret")
  add(r, local, c)
  add(r, remote, c)
  seal(r, c)
  removeFile(local)
  removeFile(remote)
  let binDir = buildCli()
  let (outp, code) = execCmdEx((binDir / "nimvault").quoteShell & " unseal --vault " &
                               r.quoteShell, workingDir = r)
  doAssert code == 0, outp
  doAssert "could not open 1 record" in outp, outp
  doAssert readFile(local) == "local-secret"
  doAssert not fileExists(remote)
  for e in loadManifest(r, verifySig = true, cfg = c):
    removeFile(findEntryFile(r, c, e.id))
  removeFile(local)
  var msg = ""
  try:
    unseal(r, c)
  except CatchableError as e:
    msg = e.msg
  doAssert "none of the 1 record(s) opens" in msg,
    "unseal called a vault it could not open empty: " & msg
  removeDir(binDir)
  removeDir(r)
  removeDir(pub)
  removeDir(foreignHome)
  echo "PASS: unseal reports the records it could not open"

block getDoesNotWritePlaintextToTheRuntimeDir:
  let shm = (if dirExists("/dev/shm"): "/dev/shm" else: getTempDir()) /
            ("nimvault-get-" & $getCurrentProcessId())
  createDir(shm)
  setFilePermissions(shm, {fpUserRead, fpUserWrite, fpUserExec})
  let oldXdg = getEnv("XDG_RUNTIME_DIR")
  putEnv("XDG_RUNTIME_DIR", shm)
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let needle = "sentinel-9f3a-unique-plaintext"
  let f = r / "secret.txt"
  writeFile(f, needle)
  add(r, f, c)
  seal(r, c)
  let marker = r / "saw-plaintext"
  let pid = fork()
  doAssert pid >= 0, "fork failed"
  if pid == 0:
    proc hunt(dir, needle, marker: string) =
      if not dirExists(dir): return
      for kind, path in walkDir(dir):
        if kind == pcFile:
          try:
            if needle in readFile(path):
              writeFile(marker, "1")
              quit(0)
          except CatchableError:
            discard
        elif kind == pcDir:
          hunt(path, needle, marker)
    for i in 0 ..< 80000:
      hunt(shm, needle, marker)
      if fileExists(marker): quit(0)
    quit(0)
  discard get(r, f, c, allowUnsigned = true)
  var status: cint
  discard waitpid(pid, status, 0)
  doAssert not fileExists(marker),
    "get must not write the plaintext into the runtime directory"
  if oldXdg.len > 0: putEnv("XDG_RUNTIME_DIR", oldXdg)
  else: delEnv("XDG_RUNTIME_DIR")
  removeDir(r)
  removeDir(shm)
  echo "PASS: get keeps the plaintext off disk"

proc holder(repo: string) {.thread.} =
  {.cast(gcsafe).}:
    var lk = acquire(repo, timeoutMs = 3000)
    sleep(700)
    release(lk)

block secondThreadCannotTakeTheLock:
  let r = setupRepo()
  var thr: Thread[string]
  createThread(thr, holder, r)
  sleep(150)
  var raised = false
  try:
    var mine = acquire(r, timeoutMs = 200)
    release(mine)
  except CatchableError:
    raised = true
  joinThread(thr)
  doAssert raised, "a second thread must not enter the vault while it is locked"
  var after = acquire(r, timeoutMs = 1000)
  release(after)
  removeDir(r)
  echo "PASS: the vault lock excludes another thread"

block pendingPromotionWaitsForTheLock:
  ## check, status and get may rename a pending blob over the live one. A
  ## seal holding the vault may be publishing that same blob, so they wait.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "promotion-under-lock")
  add(r, f, c)
  seal(r, c)
  for name in ["check", "status", "get"]:
    var thr: Thread[string]
    createThread(thr, holder, r)
    sleep(150)
    let started = epochTime()
    case name
    of "check": discard checkVault(r, c)
    of "status": discard statusReport(r, c)
    else: doAssert get(r, f, c, allowUnsigned = true) == "promotion-under-lock"
    let waited = epochTime() - started
    joinThread(thr)
    doAssert waited >= 0.4, &"{name} must wait for the vault lock (waited {waited:.2f}s)"
  removeDir(r)
  echo "PASS: check, status and get wait for the vault lock"

block listAndStatusVerifyRecordsBeforePendingPromotion:
  ## list/status must verify record signatures before trusting a record hash
  ## that could otherwise promote a pending blob.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let f = r / "secret.txt"
  writeFile(f, "pending-verify")
  add(r, f, c)
  seal(r, c)
  let entry = loadManifest(r, cfg = c)[0]
  let deks = loadDeks(r, c)
  let work = createTempDir("nimvault_audit_", "_pendingverify")
  let payload = work / "payload"
  writeFile(payload, "forged-pending")
  let pend = crypto.blobPath(r, c, entry.id) & ".pending"
  encryptWithDek(c, deks[entry.id], payload, pend)
  let forgedHash = sha256sum(pend)
  let plain = work / "record.plain"
  writeFile(plain, EntryHeader & "\n" &
    &"{entry.id}\t{entry.path}\t{forgedHash}\tfile\t{entry.contentHash}\t{deks[entry.id]}\n")
  encryptFileTo(c, @[c.recipient], plain, entryFile(r, c, entry.id), sign = false)
  var raised = false
  try:
    discard listReport(r, c)
  except CatchableError:
    raised = true
  doAssert raised, "list must verify records before trusting their metadata"
  raised = false
  try:
    discard statusReport(r, c)
  except CatchableError:
    raised = true
  doAssert raised, "status must verify records before resolving pending blobs"
  doAssert fileExists(pend),
    "status/list must not promote a pending blob from an unverified record"
  removeDir(work)
  removeDir(r)
  echo "PASS: list/status verify records before pending promotion"

block movedLockDoesNotCloseStdin:
  proc dropLock(x: sink VaultLock) =
    release(x)
  let r = setupRepo()
  dropLock(acquire(r, timeoutMs = 1000))
  doAssert fcntl(0.cint, F_GETFD) != -1, "moving a vault lock must not close stdin"
  removeDir(r)
  echo "PASS: moving a vault lock does not close stdin"

proc genKey(home, name, email: string): string =
  let script = home / (name & ".keygen")
  writeFile(script, &"""
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: {name}
Name-Email: {email}
Expire-Date: 0
%commit
""")
  let (output, code) = execCmdEx(&"gpg --batch --gen-key {script.quoteShell}")
  doAssert code == 0, output
  let (listed, lcode) = execCmdEx(
    &"gpg --list-keys --keyid-format long --with-colons {email}")
  doAssert lcode == 0, listed
  for line in listed.splitLines:
    if line.startsWith("pub:"):
      return line.split(':')[4]
  doAssert false, "no key id for " & email

block emailSpecifierMatchesExactEmailOnly:
  ## alice@example.com must not authorize malice@example.com by substring.
  let home = gpgHome("email")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  try:
    let alice = genKey(home, "Alice", "alice@example.com")
    let malice = genKey(home, "Malice", "malice@example.com")
    let af = signerFingerprints(@[alice])
    let mf = signerFingerprints(@[malice])
    doAssert af.len == 1 and mf.len == 1
    let got = signerFingerprints(@["alice@example.com"])
    doAssert got.len == 1 and got[0] == af[0], "email match must be exact: " & $got
    doAssert mf[0] notin got, "substring email match authorized malice"
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(home)
  echo "PASS: email signer specs match exact emails only"

block addUsesAnAllowedSignerNotTheGpgDefault:
  ## add/seal must pick an allowed signer explicitly, not gpg's default key.
  let home = gpgHome("localsigner")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  let r = setupRepo()
  try:
    let other = genKey(home, "Other", "other-default@nimvault.local")
    let owner = genKey(home, "Owner", "owner-allowed@nimvault.local")
    writeFile(home / "gpg.conf", "default-key " & other & "\n")
    let c = GpgConfig(recipient: owner, root: r)
    let f = r / "secret.txt"
    writeFile(f, "must-verify")
    add(r, f, c)
    seal(r, c)
    doAssert get(r, f, c) == "must-verify"
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(home)
  echo "PASS: add/seal sign with an allowed key, not gpg's default key"

block addFailsWithoutAllowedSecretKey:
  ## When only a disallowed secret key is present, add must fail instead of
  ## signing with it.
  let ownerHome = gpgHome("owner")
  let signerHome = gpgHome("signer")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", ownerHome)
  let owner = genKey(ownerHome, "Owner", "owner-only-public@nimvault.local")
  let (pub, ecode) = execCmdEx("gpg --batch --export --armor " & owner.quoteShell)
  doAssert ecode == 0, pub
  let pubPath = ownerHome / "owner.pub.asc"
  writeFile(pubPath, pub)

  putEnv("GNUPGHOME", signerHome)
  let other = genKey(signerHome, "Other", "other-only-secret@nimvault.local")
  discard other
  let (imported, icode) = execCmdEx("gpg --batch --import " & pubPath.quoteShell)
  doAssert icode == 0, imported
  let r = setupRepo()
  try:
    let c = GpgConfig(recipient: owner, root: r)
    let f = r / "secret.txt"
    writeFile(f, "must-not-sign-with-other")
    var raised = false
    try:
      add(r, f, c)
    except CatchableError as e:
      raised = true
      doAssert "allowed secret key" in e.msg, e.msg
    doAssert raised, "add must fail when no allowed signing key is present"
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(ownerHome)
    removeDir(signerHome)
  echo "PASS: add refuses to sign when no allowed secret key is present"

block recipientEmailRefusesMaliceSigner:
  ## recipient = alice@example.com must not accept a malice@example.com signer.
  let home = gpgHome("malice")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  let r = setupRepo()
  try:
    let alice = genKey(home, "Alice", "alice@example.com")
    let malice = genKey(home, "Malice", "malice@example.com")
    let c = GpgConfig(recipient: "alice@example.com", root: r)
    let real = r / "real.txt"
    writeFile(real, "real-secret")
    add(r, real, c)
    seal(r, c)

    let id = "eeeeeeeeeeeeeeee"
    let work = createTempDir("nimvault_audit_", "_forge-email")
    let payload = work / "payload"
    writeFile(payload, "planted-by-malice")
    let key = newDek(c)
    let blob = crypto.blobPath(r, c, id)
    encryptWithDek(c, key, payload, blob)
    let plain = work / "record.plain"
    writeFile(plain, EntryHeader & "\n" &
      &"{id}\tplanted.txt\t{sha256sum(blob)}\tfile\t{sha256sum(payload)}\t{key}\n")
    let rec = entryFile(r, c, id)
    let (signed, scode) = execCmdEx("gpg --batch --yes --quiet --no-options " &
      "--trust-model always --local-user " & malice.quoteShell &
      " --sign -e --recipient=" & alice.quoteShell &
      " --set-filename '' -o " & rec.quoteShell & " -- " & plain.quoteShell)
    doAssert scode == 0, signed
    removeDir(work)

    var raised = false
    try:
      unseal(r, c)
    except CatchableError as e:
      raised = true
      doAssert "signature verification failed" in e.msg, e.msg
    doAssert raised, "unseal must reject a malice@example.com signature"
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(home)
  echo "PASS: recipient email does not authorize malice signer"

block recordSignedByAnotherKeyIsRefused:
  ## GOODSIG only says some key in the keyring signed. A record signed by a
  ## key the vault is not configured for must not be trusted.
  let home = gpgHome("twokeys")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  let r = setupRepo()
  try:
    let vaultKey = genKey(home, "Vault Owner", "owner@nimvault.local")
    let otherKey = genKey(home, "Other Signer", "other@nimvault.local")
    let c = GpgConfig(recipient: vaultKey, root: r)
    let real = r / "real.txt"
    writeFile(real, "real-secret")
    add(r, real, c)
    seal(r, c)
    doAssert get(r, real, c) == "real-secret", "the vault's own records verify"

    let id = "cccccccccccccccc"
    let work = createTempDir("nimvault_audit_", "_forge")
    let payload = work / "payload"
    writeFile(payload, "planted-by-other-key")
    let key = newDek(c)
    let blob = crypto.blobPath(r, c, id)
    encryptWithDek(c, key, payload, blob)
    let plain = work / "record.plain"
    writeFile(plain, EntryHeader & "\n" &
      &"{id}\tplanted.txt\t{sha256sum(blob)}\tfile\t{sha256sum(payload)}\t{key}\n")
    let rec = entryFile(r, c, id)
    let (signed, scode) = execCmdEx("gpg --batch --yes --quiet --no-options " &
      "--trust-model always --local-user " & otherKey.quoteShell &
      " --sign -e --recipient=" & vaultKey.quoteShell &
      " --set-filename '' -o " & rec.quoteShell & " -- " & plain.quoteShell)
    doAssert scode == 0, signed
    let (status, _) = execCmdEx("gpg --batch --status-fd 1 -d -o /dev/null -- " &
                                rec.quoteShell)
    doAssert "[GNUPG:] GOODSIG" in status,
      "the forged record carries a good signature from the other key"
    removeDir(work)

    let planted = r / "planted.txt"
    var raised = false
    try:
      unseal(r, c)
    except CatchableError as e:
      raised = true
      doAssert "signature verification failed" in e.msg, e.msg
    doAssert raised, "unseal must refuse a record signed by an unconfigured key"
    doAssert not fileExists(planted), "unseal must not write the planted file"
    raised = false
    try:
      discard get(r, planted, c)
    except CatchableError:
      raised = true
    doAssert raised, "get must refuse a record signed by an unconfigured key"
    raised = false
    try:
      discard get(r, real, c)
    except CatchableError:
      raised = true
    doAssert raised, "get must refuse while any record has a foreign signer"

    var both = c
    both.wraps = @[&"**:{vaultKey},{otherKey}"]
    doAssert get(r, planted, both) == "planted-by-other-key",
      "a key named in a wrap rule is a configured signer"
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(home)
  echo "PASS: a record signed by an unconfigured key is refused"

proc gpgSignEncrypt(signer, recipient, inPath, outPath: string, sign = true) =
  let signArgs = if sign: " --local-user " & signer.quoteShell & " --sign" else: ""
  let (output, code) = execCmdEx("gpg --batch --yes --quiet --no-options " &
    "--trust-model always" & signArgs & " -e --recipient=" & recipient.quoteShell &
    " --set-filename '' -o " & outPath.quoteShell & " -- " & inPath.quoteShell)
  doAssert code == 0, output

block allowUnsignedRefusesAnUnconfiguredRecordSigner:
  ## --allow-unsigned accepts a record with no signature. A record that
  ## carries a good signature from a key the vault is not configured for is
  ## not unsigned, and must not be accepted.
  let home = gpgHome("unsignedflag")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  let r = setupRepo()
  try:
    let vaultKey = genKey(home, "Vault Owner", "owner-flag@nimvault.local")
    let otherKey = genKey(home, "Other Signer", "other-flag@nimvault.local")
    let c = GpgConfig(recipient: vaultKey, root: r)
    let real = r / "real.txt"
    writeFile(real, "real-secret")
    add(r, real, c)
    seal(r, c)
    let id = "cdcdcdcdcdcdcdcd"
    let work = createTempDir("nimvault_audit_", "_forge-flag")
    let payload = work / "payload"
    writeFile(payload, "planted-by-other-key")
    let key = newDek(c)
    let blob = crypto.blobPath(r, c, id)
    encryptWithDek(c, key, payload, blob)
    let plain = work / "record.plain"
    writeFile(plain, EntryHeader & "\n" &
      &"{id}\tplanted.txt\t{sha256sum(blob)}\tfile\t{sha256sum(payload)}\t{key}\n")
    let rec = entryFile(r, c, id)
    let planted = r / "planted.txt"
    gpgSignEncrypt(otherKey, vaultKey, plain, rec)
    var raised = false
    try:
      unseal(r, c, allowUnsigned = true)
    except CatchableError as e:
      raised = true
      doAssert "signature verification failed" in e.msg, e.msg
    doAssert raised, "unseal --allow-unsigned must refuse an unconfigured signer"
    doAssert not fileExists(planted), "unseal must not write the planted file"
    raised = false
    try:
      discard get(r, planted, c, allowUnsigned = true)
    except CatchableError:
      raised = true
    doAssert raised, "get --allow-unsigned must refuse an unconfigured signer"

    gpgSignEncrypt("", vaultKey, plain, rec, sign = false)
    raised = false
    try:
      unseal(r, c)
    except CatchableError:
      raised = true
    doAssert raised, "unseal without the flag must refuse an unsigned record"
    doAssert get(r, planted, c, allowUnsigned = true) == "planted-by-other-key",
      "the flag still accepts a record with no signature"
    removeDir(work)
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(home)
  echo "PASS: --allow-unsigned refuses a record signed by an unconfigured key"

block allowUnsignedRefusesAnUnconfiguredBlobSigner:
  ## A v5 blob carries its signature in band. With the flag, a good signature
  ## from an unconfigured key must still be refused by unseal and get.
  let home = gpgHome("unsignedblob")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  let r = setupRepo()
  try:
    let vaultKey = genKey(home, "Vault Owner", "owner-blob@nimvault.local")
    let otherKey = genKey(home, "Other Signer", "other-blob@nimvault.local")
    let c = GpgConfig(recipient: vaultKey, root: r)
    let id = "dcdcdcdcdcdcdcdc"
    let work = createTempDir("nimvault_audit_", "_forge-blob")
    let payload = work / "payload"
    writeFile(payload, "v5-blob-by-other-key")
    let blob = crypto.blobPath(r, c, id)
    createDir(r / ".vault")
    gpgSignEncrypt(otherKey, vaultKey, payload, blob)
    saveManifest(r, @[(id, "planted.txt", sha256sum(blob), ekFile,
                       sha256sum(payload))], c)
    let planted = r / "planted.txt"
    var raised = false
    try:
      unseal(r, c, allowUnsigned = true)
    except CatchableError as e:
      raised = true
      doAssert "signature verification failed" in e.msg, e.msg
    doAssert raised, "unseal --allow-unsigned must refuse a blob by an unconfigured signer"
    doAssert not fileExists(planted)
    raised = false
    try:
      discard get(r, planted, c, allowUnsigned = true)
    except CatchableError:
      raised = true
    doAssert raised, "get --allow-unsigned must refuse a blob by an unconfigured signer"

    gpgSignEncrypt("", vaultKey, payload, blob, sign = false)
    saveManifest(r, @[(id, "planted.txt", sha256sum(blob), ekFile,
                       sha256sum(payload))], c)
    raised = false
    try:
      unseal(r, c)
    except CatchableError:
      raised = true
    doAssert raised, "unseal without the flag must refuse an unsigned blob"
    unseal(r, c, allowUnsigned = true)
    doAssert readFile(planted) == "v5-blob-by-other-key",
      "the flag still accepts a blob with no signature"
    removeDir(work)
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(home)
  echo "PASS: --allow-unsigned refuses a v5 blob signed by an unconfigured key"

block allowUnsignedChecksSplitStubSignature:
  ## In split mode, --allow-unsigned still checks a stub manifest signature
  ## when one is present.
  let home = gpgHome("unsignedstub")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  let r = setupRepo()
  try:
    let owner = genKey(home, "Stub Owner", "owner-stub@nimvault.local")
    let other = genKey(home, "Stub Other", "other-stub@nimvault.local")
    let c = GpgConfig(recipient: owner, root: r)
    let f = r / "secret.txt"
    writeFile(f, "stub-secret")
    add(r, f, c)
    seal(r, c)
    let stub = manifestPath(r, c)
    let work = createTempDir("nimvault_audit_", "_stubsig")
    let plain = work / "manifest.plain"
    writeFile(plain, decryptToString(c, stub, verifySig = true))
    gpgSignEncrypt(other, owner, plain, stub)
    var raised = false
    try:
      discard get(r, f, c, allowUnsigned = true)
    except CatchableError as e:
      raised = true
      doAssert "signature verification failed" in e.msg, e.msg
    doAssert raised,
      "--allow-unsigned must reject a present split-stub signature by another key"
    removeDir(work)
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(home)
  echo "PASS: --allow-unsigned checks a present split-stub signature"

block nameSpecifierIsRefused:
  ## A spec that is neither an email nor hex went to gpg as a substring, so
  ## `recipient = Alice` let a record signed by Malice through a plain unseal.
  let home = gpgHome("names")
  let savedHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  let r = setupRepo()
  try:
    let alice = genKey(home, "Alice", "alice@example.com")
    let malice = genKey(home, "Malice", "malice@example.com")
    doAssert signerFingerprints(@["Alice"]).len == 0,
      "a name matched keys by substring: " & $signerFingerprints(@["Alice"])
    let honest = GpgConfig(recipient: alice, root: r)
    writeFile(r / "real.txt", "real-secret")
    add(r, r / "real.txt", honest)
    seal(r, honest)
    let id = "abababababababab"
    let work = createTempDir("nimvault_audit_", "_forge-name")
    let payload = work / "payload"
    writeFile(payload, "planted-by-malice")
    let key = newDek(honest)
    let blob = crypto.blobPath(r, honest, id)
    encryptWithDek(honest, key, payload, blob)
    let plain = work / "record.plain"
    writeFile(plain, EntryHeader & "\n" &
      &"{id}\tplanted.txt\t{sha256sum(blob)}\tfile\t{sha256sum(payload)}\t{key}\n")
    gpgSignEncrypt(malice, alice, plain, entryFile(r, honest, id))
    removeDir(work)
    var msg = ""
    try:
      unseal(r, GpgConfig(recipient: "Alice", root: r))
    except CatchableError as e:
      msg = e.msg
    doAssert "signature verification failed" in msg,
      "recipient Alice accepted a record signed by Malice: " & msg
    doAssert not fileExists(r / "planted.txt")

    createDir(r / ".vault")
    proc loadError(config, cli: string): string =
      writeFile(r / ".vault" / "config", config)
      try:
        discard initGpgConfig(cli, r)
      except CatchableError as e:
        return e.msg
    for (config, cli) in [("recipient = Alice\n", ""),
                          ("recipient = alice@example.com\nwrap = **:Alice\n", ""),
                          (&"recipient = {alice}\nwrap = **:{malice},Alice\n", ""),
                          ("recipient = alice@example.com\n", "Alice")]:
      let err = loadError(config, cli)
      doAssert "`Alice` does not name one key" in err,
        "config loaded with a name spec: " & config & " / " & cli & ": " & err
    for config in ["recipient = alice@example.com\n",
                   "recipient = <alice@example.com>\n",
                   &"recipient = {alice}\nwrap = **:0x{malice}\n"]:
      doAssert loadError(config, "") == "", config
  finally:
    putEnv("GNUPGHOME", savedHome)
    removeDir(r)
    removeDir(home)
  echo "PASS: a recipient that is not an email or key ID is refused"

block shortKeyIdsAreRefused:
  ## 8-hex key IDs are ambiguous and must be rejected at config load.
  let r = setupRepo()
  createDir(r / ".vault")
  let short = keyId[keyId.len - 8 .. ^1]
  proc loadError(config: string): string =
    writeFile(r / ".vault" / "config", config)
    try:
      discard initGpgConfig("", r)
    except CatchableError as e:
      return e.msg
  let recErr = loadError(&"recipient = {short}\n")
  doAssert "8-hex short key id" in recErr and "16-hex long key id" in recErr, recErr
  let wrapErr = loadError(&"recipient = {keyId}\nwrap = **:{short}\n")
  doAssert "8-hex short key id" in wrapErr, wrapErr
  doAssert loadError(&"recipient = {keyId}\n") == ""
  removeDir(r)
  echo "PASS: 8-hex key IDs are refused"

block preV6EntrySurvivesTheMoveToRecords:
  ## A v5 entry has no data key, so its per-entry record ends in an empty
  ## field. The parser stripped that tab, found five fields and dropped the
  ## record: the entry left list, unseal and check without a word.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  let old = r / "old.txt"
  writeFile(old, "v5-secret")
  createDir(r / ".vault")
  let id = "5a5a5a5a5a5a5a5a"
  let blob = crypto.blobPath(r, c, id)
  encryptFile(c, old, blob)
  saveManifest(r, @[(id, "old.txt", sha256sum(blob), ekFile, sha256sum(old))], c,
               sealKey(c))
  doAssert loadManifest(r, verifySig = true, cfg = c).len == 1
  let fresh = r / "new.txt"
  writeFile(fresh, "v6-secret")
  add(r, fresh, c)
  doAssert hasSplitEntries(r), "add should write per-entry records"
  var paths: seq[string] = @[]
  for e in loadManifest(r, verifySig = true, cfg = c):
    paths.add(e.path)
  doAssert "old.txt" in paths and "new.txt" in paths, $paths
  let rep = checkVault(r, c)
  doAssert rep.problems.len == 0 and rep.checked == 2, $rep
  removeFile(old)
  removeFile(fresh)
  unseal(r, c)
  doAssert readFile(old) == "v5-secret"
  doAssert readFile(fresh) == "v6-secret"
  removeDir(r)
  echo "PASS: a pre-v6 entry keeps its record after add"

block recordThatHoldsNoEntryIsCounted:
  ## A record that opened and verified but held no entry line was dropped,
  ## and check called the rest consistent.
  let r = setupRepo()
  let c = GpgConfig(recipient: keyId, root: r)
  writeFile(r / "kept.txt", "kept-secret")
  add(r, r / "kept.txt", c)
  seal(r, c)
  let work = createTempDir("nimvault_audit_", "_unparsed")
  writeFile(work / "record.plain", EntryHeader & "\nnot-an-entry\n")
  encryptFileTo(c, @[c.recipient], work / "record.plain",
                entryFile(r, c, "6b6b6b6b6b6b6b6b"))
  removeDir(work)
  let rep = checkVault(r, c)
  doAssert "1 record(s) open but hold no entry this version can read" in
    rep.problems, $rep
  var msg = ""
  try:
    check(r, c)
  except CatchableError as e:
    msg = e.msg
  doAssert "inconsistent" in msg, "check passed over a record it dropped: " & msg
  removeFile(r / "kept.txt")
  msg = ""
  try:
    unseal(r, c)
  except CatchableError as e:
    msg = e.msg
  doAssert "hold no entry" in msg, "unseal dropped a record: " & msg
  doAssert not fileExists(r / "kept.txt")
  removeDir(r)
  echo "PASS: check and unseal count a record that holds no entry"

block symlinkedHomeAndVaultRootAreNotRefused:
  ## The base was compared as spelled and the path under it fully resolved,
  ## so a HOME or a vault root reached through a symlink refused every file.
  let r = setupRepo()
  let realRepo = setupRepo()
  let top = createTempDir("nimvault_audit_", "_linkedbase")
  let realHome = top / "real-home"
  createDir(realHome / "dotfiles")
  createSymlink(realHome, top / "home")
  createSymlink(realHome / "dotfiles", realHome / ".dot")
  let savedHome = getEnv("HOME")
  putEnv("HOME", top / "home")
  try:
    let c = GpgConfig(recipient: keyId)
    let plainFile = top / "home" / "token.txt"
    let viaDirLink = top / "home" / ".dot" / "rc.txt"
    writeFile(plainFile, "home-secret")
    writeFile(viaDirLink, "dot-secret")
    add(r, plainFile, c)
    add(r, viaDirLink, c)
    seal(r, c)
    removeFile(plainFile)
    removeFile(viaDirLink)
    unseal(r, c)
    doAssert readFile(plainFile) == "home-secret"
    doAssert readFile(viaDirLink) == "dot-secret"
  finally:
    putEnv("HOME", savedHome)

  createDir(realRepo / "real-sub")
  createSymlink(realRepo / "real-sub", realRepo / "sub")
  let linkRepo = top / "vault"
  createSymlink(realRepo, linkRepo)
  let rc = GpgConfig(recipient: keyId, root: linkRepo)
  let g = linkRepo / "sub" / "x.txt"
  writeFile(g, "root-secret")
  add(linkRepo, g, rc)
  seal(linkRepo, rc)
  removeFile(g)
  unseal(linkRepo, rc)
  doAssert readFile(g) == "root-secret"
  removeDir(r)
  removeDir(realRepo)
  removeDir(top)
  echo "PASS: a HOME or vault root reached through a symlink is not refused"

block subkeyRecipientOpensTheVault:
  ## A vault may name the encryption subkey it is sealed to. The signer lookup
  ## matched only primary keys, so such a vault could neither sign nor verify.
  let (listed, lcode) = execCmdEx("gpg --batch --with-colons --list-keys " &
                                  keyId.quoteShell)
  doAssert lcode == 0, listed
  var subId = ""
  for line in listed.splitLines:
    if line.startsWith("sub:"):
      subId = line.split(':')[4]
  doAssert subId.len == 16 and subId != keyId, listed
  for spec in [subId, subId & "!"]:
    let r = setupRepo()
    createDir(r / ".vault")
    writeFile(r / ".vault" / "config", &"recipient = {spec}\nroot = repo\n")
    let c = initGpgConfig("", r)
    doAssert c.recipient == spec
    writeFile(r / "s.txt", "subkey-secret")
    add(r, r / "s.txt", c)
    seal(r, c)
    removeFile(r / "s.txt")
    unseal(r, c)
    doAssert readFile(r / "s.txt") == "subkey-secret"
    doAssert get(r, r / "s.txt", c) == "subkey-secret"
    removeDir(r)
  echo "PASS: a recipient that names the encryption subkey opens the vault"

if sharedCliDir.len > 0:
  removeDir(sharedCliDir)
removeDir(creds.home)
delEnv("GNUPGHOME")
echo "All audit tests passed."
