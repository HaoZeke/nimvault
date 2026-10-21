## Behaviour the vault must keep: a failed seal, a symlink, a hook, a lock.
##
## Throwaway GPG home. No long-lived key material.

import std/[os, osproc, posix, strutils, strformat, streams, tables, tempfiles]
import nimvault/[gpg, manifest, commands, crypto, dek, lock]

proc setupGpg(): tuple[home, key: string] =
  result.home = createTempDir("nimvault_audit_", "_gpg")
  setFilePermissions(result.home, {fpUserRead, fpUserWrite, fpUserExec})
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
    lockPlaintext(r, unsigned)
    doAssert readFile(thesisBackup) == "thesis-draft",
      "lock must not shred backups of an entry that is not present"
    forgeUnsignedRecord(r, c, "bbbbbbbbbbbbbbbb", "~/../outside/notes")
    raised = false
    try:
      lockPlaintext(r, unsigned)
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

block unsealDoesNotCopyThroughFinalSymlink:
  ## Runtime dir and the vault are on different devices. moveFile then copies,
  ## and a copy follows a symlink planted at the destination.
  let shm = "/dev/shm/nimvault-audit-" & $getCurrentProcessId()
  createDir(shm)
  setFilePermissions(shm, {fpUserRead, fpUserWrite, fpUserExec})
  if devOf(shm) == devOf(getTempDir()):
    removeDir(shm)
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
  createSymlink("/dev/shm", parent)
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
  doAssert "nimvault check" in push
  removeDir(r)
  echo "PASS: hooks scan the index and the pushed commits"

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
  let pubHome = createTempDir("nimvault_audit_", "_pub")
  setFilePermissions(pubHome, {fpUserRead, fpUserWrite, fpUserExec})
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

block getDoesNotWritePlaintextToTheRuntimeDir:
  let shm = "/dev/shm/nimvault-get-" & $getCurrentProcessId()
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

block recordSignedByAnotherKeyIsRefused:
  ## GOODSIG only says some key in the keyring signed. A record signed by a
  ## key the vault is not configured for must not be trusted.
  let home = createTempDir("nimvault_audit_", "_twokeys")
  setFilePermissions(home, {fpUserRead, fpUserWrite, fpUserExec})
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

removeDir(creds.home)
delEnv("GNUPGHOME")
echo "All audit tests passed."
