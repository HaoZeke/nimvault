## Vault commands: seal, unseal, add, rm, mv, list, status, scan.
##
## All commands take a repo path and GpgConfig.
## Parallel GPG via startProcess with direct invocation (no shell).

import std/[os, osproc, strutils, strformat, streams, terminal, re, sets, sequtils,
            tables, posix]
import ./gpg, ./manifest, ./crypto, ./lock, ./dek, ./fsat
# NimvaultError, nvRaise, nvQuiet from gpg

proc recordsNeedSig(cfg: GpgConfig): bool =
  ## `signer = none` vaults have no record signature to check.
  cfg.effectiveSigner != "none"

proc banner(msg: string) =
  if nvQuiet: return
  let w = terminalWidth()
  let line = repeat('-', min(w, 72))
  echo ""
  echo line
  styledEcho fgCyan, styleBright, "  ", msg
  echo line

proc nvEcho(msg: string) =
  ## Progress output for CLI; suppressed when nvQuiet (C ABI / MCP in-process).
  if nvQuiet: return
  echo msg

proc assertStoreable(path: string) =
  ## The record is a single TSV line. A tab or newline in the path shifts
  ## columns, so the hash and the data key are no longer the fields they claim.
  if '\n' in path or '\r' in path or '\t' in path or '\0' in path:
    nvRaise("FATAL: path contains a character the manifest cannot store")

proc normalizedBase(path: string): string =
  let n = normalizedPath(path)
  if n == "/":
    "/"
  else:
    n.strip(leading = false, trailing = true, chars = {'/'})

proc insideBase(base, path: string): bool =
  let n = normalizedPath(path)
  if base == "/":
    n.startsWith("/")
  else:
    n == base or n.startsWith(base & "/")

proc boundaryBase(cfg: GpgConfig, dest: string): string =
  if cfg.root.len > 0:
    return normalizedBase(cfg.root)
  let home = normalizedBase(getHomeDir())
  if insideBase(home, dest):
    home
  else:
    ""

proc resolvedBase(base: string): string =
  ## `base` with its symlinks resolved, to compare with an `expandFilename`
  ## result, which resolves those too.
  try:
    normalizedBase(expandFilename(base))
  except OSError:
    base

proc assertResolvedWithinBoundary(cfg: GpgConfig, absPath: string) =
  ## A lexical ~/ path can still resolve outside HOME through a symlink.
  let base = boundaryBase(cfg, absPath)
  if base.len == 0:
    return
  let real = expandFilename(absPath)
  if not insideBase(resolvedBase(base), real):
    nvRaise(&"FATAL: refusing path outside the vault root: {absPath}")

proc assertParentWithinBoundary(cfg: GpgConfig, dest, absDir: string) =
  ## `absDir` is the parent of `dest`, resolved as far as currently-existing
  ## components go. The final file may not exist yet, so this check is
  ## lexical against the resolved boundary root. The boundary comes from
  ## `dest` as written: with no root, a path under $HOME stays under $HOME
  ## however its parents resolve by now.
  let base = boundaryBase(cfg, dest)
  if base.len == 0:
    return
  if not insideBase(resolvedBase(base), normalizedPath(absDir)):
    nvRaise(&"FATAL: refusing path outside the vault root: {absDir}")

proc assertAncestorsContained(cfg: GpgConfig, repo, path, verb: string) =
  ## Refuse a directory symlink above `path` that resolves outside the vault
  ## root (or $HOME). The final component is the caller's to judge.
  if not isPathSafe(cfg, storePath(cfg, path, repo)):
    nvRaise(&"FATAL: refusing to {verb} outside the vault root: {path}")
  let base = boundaryBase(cfg, path)
  if base.len == 0:
    return
  if not insideBase(base, path):
    nvRaise(&"FATAL: refusing to {verb} outside the vault root: {path}")
  let parent = path.parentDir
  if parent.len == 0:
    return
  let rel = relativePath(parent, base)
  if rel.startsWith(".."):
    nvRaise(&"FATAL: refusing to {verb} through a directory symlink: {path}")
  let real = resolvedBase(base)
  var acc = base
  for part in rel.split(DirSep):
    if part.len == 0 or part == ".":
      continue
    if part == "..":
      nvRaise(&"FATAL: refusing to {verb} through a directory symlink: {path}")
    acc = acc / part
    if symlinkExists(acc):
      if not insideBase(real, expandFilename(acc)):
        nvRaise(&"FATAL: refusing to {verb} through a directory symlink: {path}")
    elif not dirExists(acc):
      break

proc assertWritePath(cfg: GpgConfig, repo, dest: string) =
  ## The final path may itself be a symlink: `rename` replaces it.
  ## `createDir` would follow an ancestor and write the plaintext outside.
  assertAncestorsContained(cfg, repo, dest, "write")

proc assertReadPath(cfg: GpgConfig, repo, src: string) =
  ## Plaintext a record names is read only from inside the vault root (or
  ## $HOME). A swapped directory or file symlink would otherwise put another
  ## file's bytes into the blob that record vouches for.
  assertAncestorsContained(cfg, repo, src, "read")
  assertResolvedWithinBoundary(cfg, src)

type StagedPath = ref object
  ## One entry's plaintext staged beside its destination: the opened parent
  ## directory and the staging file created in it. Both stay open only until
  ## that entry is placed or discarded.
  dirFd: cint
  fd: cint
  dirPath: string
  destPath: string
  destName: string
  tmpName: string
  boundaryBase: string
  boundaryReal: string
  placed: bool

when defined(nimvaultTest):
  ## Test seam: run after the pre-rename checks and before renameat.
  var unsealBeforeRenameHook*: proc(destPath: string) {.closure.}

proc resolvedParentForWrite(path: string): string =
  ## Resolve the existing prefix of `path.parentDir` once, then append any
  ## missing tail components. This keeps symlinked HOME/root paths working
  ## while still letting the later descriptor walk refuse swapped symlinks.
  var parent = normalizedPath(path.parentDir)
  if parent.len == 0:
    parent = "/"
  if dirExists(parent):
    return normalizedPath(expandFilename(parent))
  var missing: seq[string] = @[]
  var cur = parent
  while cur.len > 1 and not dirExists(cur):
    missing.insert(cur.extractFilename, 0)
    cur = cur.parentDir
  if not dirExists(cur):
    nvRaise(&"FATAL: cannot resolve parent directory: {path}")
  result = normalizedPath(expandFilename(cur))
  for part in missing:
    result = result / part

proc openDirFd(path: string, createMissing: bool): cint =
  ## Open `path` without following directory symlinks. Missing components are
  ## created when `createMissing` is true.
  let norm = normalizedPath(path)
  if not norm.isAbsolute:
    nvRaise(&"FATAL: expected an absolute path, got: {path}")
  let flags = posix.O_RDONLY or ODirectory or ONoFollow or O_CLOEXEC
  result = posix.open("/".cstring, flags)
  if result < 0:
    nvRaise("FATAL: cannot open / for secure path walk")
  if norm == "/":
    return
  for part in norm.split(DirSep):
    if part.len == 0 or part == ".":
      continue
    if part == "..":
      discard posix.close(result)
      nvRaise(&"FATAL: refusing parent component in path: {path}")
    var next = openAt(result, part.cstring, flags)
    if next < 0 and createMissing and posix.errno == posix.ENOENT:
      if mkdirAt(result, part.cstring, 0o777.Mode) != 0 and posix.errno != posix.EEXIST:
        discard posix.close(result)
        nvRaise(&"FATAL: cannot create destination directory under {path}")
      next = openAt(result, part.cstring, flags)
    if next < 0:
      discard posix.close(result)
      if posix.errno == posix.ELOOP:
        nvRaise(&"FATAL: refusing directory symlink on write path: {path}")
      nvRaise(&"FATAL: cannot open destination directory: {path}")
    discard posix.close(result)
    result = next

proc stageBeside(dest: string, cfg: GpgConfig): StagedPath =
  ## Create the staging file under an opened parent descriptor and keep it
  ## open. The plaintext is written through that descriptor, so a later swap
  ## of a name in the path cannot redirect it.
  let parent = resolvedParentForWrite(dest)
  assertParentWithinBoundary(cfg, dest, parent)
  let dirFd = openDirFd(parent, createMissing = true)
  let tmpName = ".nimvault-" & genId() & ".tmp"
  let fd = openAt(dirFd, tmpName.cstring,
                  posix.O_WRONLY or posix.O_CREAT or posix.O_EXCL or
                  O_CLOEXEC or ONoFollow, 0o600.Mode)
  if fd < 0:
    discard posix.close(dirFd)
    nvRaise(&"FATAL: cannot create temporary plaintext in {parent}")
  let base = boundaryBase(cfg, dest)
  result = StagedPath(
    dirFd: dirFd,
    fd: fd,
    dirPath: parent,
    destPath: normalizedPath(dest),
    destName: dest.extractFilename,
    tmpName: tmpName,
    boundaryBase: base,
    boundaryReal: if base.len > 0: resolvedBase(base) else: "")

proc openParentFromBoundary(sp: StagedPath): cint =
  ## Re-open the destination parent by the path as written, from the boundary
  ## root, with O_NOFOLLOW on every component.
  if sp.boundaryBase.len == 0 or sp.boundaryReal.len == 0:
    return -1
  let parent = normalizedPath(sp.destPath.parentDir)
  if not insideBase(sp.boundaryBase, parent):
    return -1
  let rel = relativePath(parent, sp.boundaryBase)
  let flags = posix.O_RDONLY or ODirectory or ONoFollow or O_CLOEXEC
  result = openDirFd(sp.boundaryReal, createMissing = false)
  if rel.len == 0 or rel == ".":
    return
  for part in rel.split(DirSep):
    if part.len == 0 or part == ".":
      continue
    if part == "..":
      discard posix.close(result)
      return -1
    let next = openAt(result, part.cstring, flags)
    if next < 0:
      discard posix.close(result)
      return -1
    discard posix.close(result)
    result = next

proc parentStillBound(sp: StagedPath): bool =
  if sp.boundaryBase.len == 0:
    return true
  template sameAsHeld(fdNow: cint): bool =
    (var held, current: Stat;
     fstat(sp.dirFd, held) == 0 and
     fstat(fdNow, current) == 0 and
     sameFile(held, current))
  var nowFd = -1.cint
  try:
    nowFd = openParentFromBoundary(sp)
  except CatchableError:
    nowFd = -1
  if nowFd >= 0:
    result = sameAsHeld(nowFd)
    discard posix.close(nowFd)
    if result:
      return
  # Paths under symlinked HOME/root are allowed when their resolved parent is
  # still inside the same boundary and inode as the one already opened.
  try:
    let parent = resolvedParentForWrite(sp.destPath)
    if not insideBase(sp.boundaryReal, parent):
      return false
    nowFd = openDirFd(parent, createMissing = false)
  except CatchableError:
    return false
  if nowFd < 0:
    return false
  result = sameAsHeld(nowFd)
  discard posix.close(nowFd)

proc stillNamed(sp: StagedPath): bool =
  ## Whether the staging name still refers to the file this process created.
  var mine, named: Stat
  fstat(sp.fd, mine) == 0 and
    fstatAt(sp.dirFd, sp.tmpName.cstring, named, AtSymlinkNoFollow) == 0 and
    sameFile(mine, named)

proc destStillNamed(sp: StagedPath): bool =
  ## Whether the destination name still refers to this staged file.
  var mine, named: Stat
  fstat(sp.fd, mine) == 0 and
    fstatAt(sp.dirFd, sp.destName.cstring, named, AtSymlinkNoFollow) == 0 and
    sameFile(mine, named)

proc discardStaged(sp: StagedPath) =
  ## Close the entry's descriptors. A staging file that was not placed is
  ## overwritten through its own descriptor, then unlinked while its name
  ## still refers to it. Unlink alone is not enough; the bytes are the
  ## plaintext.
  if sp.fd >= 0:
    if not sp.placed:
      overwriteFd(sp.fd)
      if stillNamed(sp):
        discard unlinkAt(sp.dirFd, sp.tmpName.cstring, 0)
    discard posix.close(sp.fd)
    sp.fd = -1
  if sp.dirFd >= 0:
    discard posix.close(sp.dirFd)
    sp.dirFd = -1

proc placeStaged(sp: StagedPath, job: Drain) =
  ## Mode 0600, or 0700 for a shebang script, then rename the staging file
  ## over the destination through the descriptor it was created under. One
  ## directory, so a symlink at the destination is replaced, not followed.
  let dest = sp.destPath
  let mode = if job.head == "#!": 0o700.Mode else: 0o600.Mode
  if posix.fchmod(sp.fd, mode) != 0:
    nvRaise(&"FATAL: cannot set the mode of the plaintext for {dest}")
  if not stillNamed(sp):
    nvRaise(&"FATAL: the staging file for {dest} was replaced")
  if not parentStillBound(sp):
    overwriteFd(sp.fd)
    if stillNamed(sp):
      discard unlinkAt(sp.dirFd, sp.tmpName.cstring, 0)
    nvRaise(&"FATAL: destination parent changed while unsealing: {dest}")
  when defined(nimvaultTest):
    if unsealBeforeRenameHook != nil:
      unsealBeforeRenameHook(sp.destPath)
  if renameAt(sp.dirFd, sp.tmpName.cstring, sp.dirFd, sp.destName.cstring) != 0:
    nvRaise(&"FATAL: could not place plaintext at {dest}")
  if not parentStillBound(sp):
    overwriteFd(sp.fd)
    if destStillNamed(sp):
      discard unlinkAt(sp.dirFd, sp.destName.cstring, 0)
    nvRaise(&"FATAL: destination parent changed while unsealing: {dest}")
  sp.placed = true

proc decryptFailure(e: VaultEntry, job: Drain): string =
  ## Why one entry's decryption is refused, or "".
  if job.code != 0:
    return &"FATAL: failed to unseal {e.path}\n{job.err.strip}"
  if job.writeErr != 0:
    return &"FATAL: failed to unseal {e.path}\n  cannot write the staging " &
           "file: " & osErrorMsg(OSErrorCode(job.writeErr))
  ""

proc gitignorePattern(rel: string): string =
  ## A gitignore line for this path alone. A leading `#` is a comment, a
  ## leading `!` is a negation, and `*` is a glob, so the written line is
  ## anchored and those characters are escaped.
  result = "/"
  for c in rel:
    if c in {'*', '?', '[', '\\'}:
      result.add('\\')
    result.add(c)
  if result.len > 1 and result[^1] == ' ':
    result = result[0 ..< ^1] & "\\ "

proc toAbs(cfg: GpgConfig, path: string): string =
  ## Resolve a user-supplied path the way `add`, `rm` and `get` already do, so
  ## every command accepts the same spellings of the same file.
  if path.isAbsolute: path
  elif path.startsWith("~/"): expandHome(path)
  elif cfg.root.len > 0: cfg.root / path
  else: expandHome(path)

proc selectEntries(cfg: GpgConfig, entries: seq[VaultEntry],
                   only: seq[string]): seq[VaultEntry] =
  ## Narrow the manifest to the entries the caller named. A selector matches a
  ## single entry by path, or every entry beneath it when it names a directory.
  ##
  ## A selector that matches nothing is an error rather than a quiet no-op. The
  ## caller asked for something specific; unsealing zero files and reporting
  ## success would look identical to having done the work.
  for sel in only:
    let abs = toAbs(cfg, sel)
    let prefix = abs & "/"
    var matched = 0
    for e in entries:
      let resolved = resolvePath(cfg, e.path)
      if resolved == abs or resolved.startsWith(prefix):
        if not result.anyIt(it.id == e.id):
          result.add(e)
        inc matched
    if matched == 0:
      nvRaise(&"Not in vault: {sel}")

proc persistDeks(repo: string, cfg: GpgConfig, deks: DekTable,
                 entries: seq[VaultEntry]) =
  ## Write the live data keys, grouped the way the current wrap rules say.
  ## Callers pass the entry list they are about to persist so a removed id
  ## is not written back into the default group.
  var live: DekTable
  var groupOf = initTable[string, string]()
  var recipsOf = initTable[string, seq[string]]()
  for e in entries:
    if deks.hasKey(e.id):
      live[e.id] = deks[e.id]
    let recips = recipientsFor(cfg, e.path)
    let gid = groupId(recips)
    groupOf[e.id] = gid
    recipsOf[gid] = recips
  if live.len == 0:
    # Only drop key files this identity can open. Unread wrap-group
    # files belong to another machine.
    for path in keyFiles(repo, cfg):
      try:
        discard decryptToString(cfg, path, false)
        removeFile(path)
      except CatchableError:
        discard
    return
  saveDeksGrouped(repo, cfg, live, groupOf, recipsOf)

proc trackGitignore(repo, absPath, storedPath: string, cfg: GpgConfig,
                    noGitignore: bool) =
  var gitPath = storedPath
  if gitPath.startsWith("~/") or isAbsolute(gitPath):
    try:
      gitPath = relativePath(absPath, repo)
    except ValueError:
      gitPath = absPath.extractFilename
  if gitPath.startsWith(".."):
    gitPath = absPath.extractFilename
  let checkPath = gitPath
  let (_, lsCode) = execCmdEx(&"git ls-files --error-unmatch -- {checkPath.quoteShell}",
    workingDir = repo)
  if lsCode == 0:
    stderr.writeLine &"FATAL: {storedPath} is already tracked by git"
    nvRaise(&"  Run 'git rm --cached -- {checkPath.quoteShell}' to untrack it first.")
  let (_, gitCheckCode) = execCmdEx(&"git check-ignore -q -- {checkPath.quoteShell}",
    workingDir = repo)
  if gitCheckCode != 0:
    if noGitignore:
      stderr.writeLine &"WARNING: {storedPath} is NOT gitignored"
    else:
      let gitignorePath = repo / ".gitignore"
      var f: File
      if open(f, gitignorePath, fmAppend):
        f.writeLine(gitignorePattern(gitPath))
        f.close()
        stderr.writeLine &"Added {gitPath} to .gitignore"
      else:
        stderr.writeLine &"WARNING: {storedPath} is NOT gitignored -- could not write .gitignore"

proc addOneFile(repo, absPath: string, cfg: GpgConfig, noGitignore: bool,
                entries: var seq[VaultEntry], deks: var DekTable) =
  ## Encrypt one file under a fresh data key and append the entry. Shared by
  ## `add` and `addDir` so a new file in a sealed vault is v6 from the start.
  for e in entries:
    if resolvePath(cfg, e.path) == absPath:
      nvRaise(&"Already in vault: {storePath(cfg, absPath, repo)}")
  if symlinkExists(absPath):
    nvRaise(&"FATAL: refusing symlink: {absPath}")
  if not fileExists(absPath):
    nvRaise(&"FATAL: file not found: {absPath}")
  assertResolvedWithinBoundary(cfg, absPath)
  let storedPath = storePath(cfg, absPath, repo)
  assertStoreable(storedPath)
  assertStoreable(absPath)
  trackGitignore(repo, absPath, storedPath, cfg, noGitignore)
  let id = genId()
  let outPath = crypto.blobPath(repo, cfg, id)
  let key = newDek(cfg)
  encryptWithDek(cfg, key, absPath, outPath)
  deks[id] = key
  entries.add((id, storedPath, sha256sum(outPath), ekFile, sha256sum(absPath)))
  nvEcho(&"  {storedPath}")

type BlobSnapshot = object
  cipher: string

proc discardSnapshot(snap: var BlobSnapshot) =
  snap.cipher.setLen(0)

proc assertBlobMatches(repo: string, cfg: GpgConfig, e: VaultEntry,
                       requireSig: bool) =
  let inPath = resolveBlob(repo, cfg, e.id, e.hash)
  if inPath.len == 0:
    if e.hash.len > 0:
      stderr.writeLine &"FATAL: integrity check failed for {e.path}"
      nvRaise("  The vault blob may have been tampered with.")
    nvRaise(&"FATAL: vault blob missing: {crypto.blobPath(repo, cfg, e.id)}")
  if not fileExists(inPath):
    nvRaise(&"FATAL: vault blob missing: {inPath}")
  if e.hash.len > 0:
    let actualHash = sha256sum(inPath)
    if actualHash != e.hash:
      stderr.writeLine &"FATAL: integrity check failed for {e.path}"
      stderr.writeLine &"  Expected: {e.hash}"
      stderr.writeLine &"  Actual:   {actualHash}"
      nvRaise("  The vault blob may have been tampered with.")
  elif requireSig:
    stderr.writeLine &"FATAL: missing blob hash for {e.path} (v1 manifest)"
    nvRaise("  Pass --allow-unsigned to accept unsigned vaults.")

proc snapshotBlob(repo: string, cfg: GpgConfig, e: VaultEntry,
                  requireSig: bool): BlobSnapshot =
  ## Hash and decrypt the same bytes by decrypting the in-memory ciphertext.
  assertBlobMatches(repo, cfg, e, requireSig)
  let inPath = resolveBlob(repo, cfg, e.id, e.hash)
  result.cipher = readFile(inPath)
  if e.hash.len > 0 and sha256sumBytes(result.cipher) != e.hash:
    stderr.writeLine &"FATAL: integrity check failed for {e.path}"
    nvRaise("  The vault blob may have been tampered with.")

proc deksForEntries(repo: string, cfg: GpgConfig, entries: seq[VaultEntry],
                    verified: DekTable): DekTable =
  ## Data keys from verified records, with keys.* only as a fallback.
  result = verified
  var missing = false
  for e in entries:
    if e.id notin result:
      missing = true
      break
  if not missing:
    return
  let fromKeys = loadDeksFromKeys(repo, cfg)
  for e in entries:
    if e.id notin result and e.id in fromKeys:
      result[e.id] = fromKeys[e.id]

proc keyFileOnlyDekEntries(repo: string, cfg: GpgConfig, entries: seq[VaultEntry],
                           verified: DekTable): seq[VaultEntry] =
  ## Entries whose DEK is available only from unsigned keys.* files.
  let fromKeys = loadDeksFromKeys(repo, cfg)
  for e in entries:
    if e.id notin verified and e.id in fromKeys:
      result.add(e)

proc refuseUnsignedDekResign(entries: seq[VaultEntry], action: string) =
  var paths: seq[string] = @[]
  for e in entries:
    paths.add(e.path)
  nvRaise("FATAL: refusing to " & action & " with record DEKs loaded only " &
          "from unsigned keys.*:\n  " & paths.join("\n  ") & "\n" &
          "  Run 'nimvault seal --force' to mint signed record DEKs first.")

proc unseal*(repo: string, cfg: GpgConfig, allowUnsigned = false,
             only: seq[string] = @[]) =
  ## Decrypt tracked entries back to their target paths. With no selector this
  ## restores the whole vault; with one it restores only what was named.
  ##
  ## The selective form exists because all-or-nothing forces the caller to
  ## express any partial restore somewhere else. A machine that should hold a
  ## subset of the vault otherwise has to model that split in whatever tool
  ## sits above this one, which is both duplicated and invisible from here.
  let lk {.used.} = acquire(repo)
  let requireSig = not allowUnsigned
  let meta = loadManifestMeta(repo, verifySig = requireSig, cfg = cfg,
                              checkPresent = true)
  let allEntries = meta.entries
  if meta.unparsed > 0:
    nvRaise(&"FATAL: {meta.unparsed} record(s) open but hold no entry this " &
            "version can read.\n  Refusing to unseal part of the vault; run " &
            "`nimvault check`.")
  if allEntries.len == 0 and meta.unopened > 0:
    nvRaise(&"FATAL: none of the {meta.unopened} record(s) opens with the " &
            "keys on this machine.\n" &
            "  Import the secret key of the recipient or of a wrap group.")
  if allEntries.len == 0:
    nvEcho("vault is empty")
    return
  if meta.unopened > 0:
    stderr.writeLine(&"  could not open {meta.unopened} record(s) with this " &
                     "machine's secret keys")

  let entries = if only.len == 0: allEntries
                else: selectEntries(cfg, allEntries, only)

  if only.len == 0:
    banner("Unsealing vault ...")
  else:
    banner(&"Unsealing {entries.len} of {allEntries.len} entries ...")

  # Verify blob integrity and path safety before any decryption
  for e in entries:
    # Path traversal check
    if not isPathSafe(cfg, e.path):
      stderr.writeLine &"FATAL: unsafe path in manifest: {e.path}"
      stderr.writeLine &"  Resolved: {normalizedPath(resolvePath(cfg, e.path))}"
      nvRaise("  Possible directory traversal attack.")
    let dest = resolvePath(cfg, e.path)
    assertWritePath(cfg, repo, dest)
    assertBlobMatches(repo, cfg, e, requireSig)

  # Decrypt beside the destination, not under the runtime directory.
  # rename() stays on one filesystem and replaces a symlink at the final
  # path. moveFile's copy fallback follows that symlink when the runtime
  # directory is a different device, which is the usual split between
  # XDG_RUNTIME_DIR and $HOME.
  # The staging file is created 0600. umask 077 keeps a missing parent
  # directory owner-only as well.

  # A vault may hold both formats while a migration drains: an entry with a
  # data key is v6, one without is encrypted straight to the recipient. The
  # key file is the discriminator, and it cannot disagree with the blob because
  # a key is only ever written by the encryption that used it.
  let deks = deksForEntries(repo, cfg, allEntries, meta.deks)
  var enveloped, direct: seq[VaultEntry]
  for e in entries:
    if deks.hasKey(e.id): enveloped.add(e) else: direct.add(e)

  let inBandChecked = cfg.signaturesInBand and direct.len > 0
  if inBandChecked:
    # Direct gpg blobs prove authenticity in-band while decrypting. Verify all
    # of them before placing any plaintext, so a later bad signature cannot
    # leave earlier files restored.
    for e in direct:
      var snap: BlobSnapshot
      try:
        snap = snapshotBlob(repo, cfg, e, requireSig)
        discard decryptBytesToString(cfg, snap.cipher, e.path,
                                     verifySig = requireSig,
                                     checkPresent = true)
      finally:
        discardSnapshot(snap)

  # Each entry is staged, decrypted from the exact bytes hashed in
  # `snapshotBlob`, and placed before the next starts. A failure stops the run;
  # what was already placed passed every check above.
  var placed = 0
  template refuse(problem: string) =
    nvRaise(if placed == 0: problem
            else: problem & &"\n  {placed} of {entries.len} file(s) were " &
                  "restored before this one.")
  proc stagedWrite(plain: string, sp: StagedPath): Drain =
    if plain.len > 0:
      result.writeErr = writeAll(sp.fd, unsafeAddr plain[0], plain.len)
      let keep = min(2, plain.len)
      result.head = plain[0 ..< keep]

  withPrivateUmask:
    for e in enveloped:
      let sp = stageBeside(resolvePath(cfg, e.path), cfg)
      var snap: BlobSnapshot
      try:
        snap = snapshotBlob(repo, cfg, e, requireSig)
        let plain = decryptWithDekBytesToString(cfg, deks[e.id], snap.cipher)
        let staged = stagedWrite(plain, sp)
        let problem = decryptFailure(e, staged)
        if problem.len > 0:
          refuse(problem)
        placeStaged(sp, staged)
      finally:
        discardStaged(sp)
        discardSnapshot(snap)
      inc placed
      nvEcho(&"  {e.path}")

    for e in direct:
      let sp = stageBeside(resolvePath(cfg, e.path), cfg)
      var snap: BlobSnapshot
      try:
        snap = snapshotBlob(repo, cfg, e, requireSig)
        let plain = decryptBytesToString(cfg, snap.cipher, e.path,
          verifySig = (if inBandChecked: false else: requireSig),
          checkPresent = (if inBandChecked: false else: true))
        let staged = stagedWrite(plain, sp)
        let problem = decryptFailure(e, staged)
        if problem.len > 0:
          refuse(problem)
        placeStaged(sp, staged)
      finally:
        discardStaged(sp)
        discardSnapshot(snap)
      inc placed
      nvEcho(&"  {e.path}")

  nvEcho(&"\nUnsealed {entries.len} file(s).")

proc pendingId(path: string): string =
  let name = path.extractFilename
  if name.endsWith(".gpg.pending"):
    return name[0 ..< (name.len - ".gpg.pending".len)]
  if name.endsWith(".age.pending"):
    return name[0 ..< (name.len - ".age.pending".len)]
  name.split('.')[0]

proc discardPendingUnlessRecorded(repo: string, cfg: GpgConfig,
                                  paths: seq[string]) =
  ## Drop pending ciphertext the record does not name. A record that already
  ## names it is the durable copy; the next read promotes the file. When the
  ## records cannot be read, leave every pending file for that read.
  var named = initHashSet[string]()
  var known = true
  try:
    for ent in loadManifest(repo, verifySig = recordsNeedSig(cfg), cfg = cfg):
      if ent.hash.len > 0:
        named.incl(ent.id & "\t" & ent.hash)
  except CatchableError:
    known = false
  if not known:
    return
  for pend in paths:
    if not fileExists(pend):
      continue
    let key = pendingId(pend) & "\t" & sha256sum(pend)
    if key notin named:
      try: removeFile(pend) except CatchableError: discard

proc seal*(repo: string, cfg: GpgConfig, force = false) =
  ## Encrypt every tracked file whose plaintext changed since the last seal.
  ##
  ## Encryption output is not deterministic: GPG and age both draw a fresh
  ## session key per run, so re-encrypting a file nobody edited still produces
  ## a different blob. Sealing unconditionally therefore rewrote every blob in
  ## the repo on every run, and a one-file change arrived as a diff touching
  ## the whole vault. Files are skipped when the plaintext hash, the blob and
  ## the blob's own hash all still agree with the manifest. `force` re-encrypts
  ## regardless, as does any change to the seal key.
  # Mutating command: hold the vault lock so a concurrent nimvault
  # cannot read this manifest, write its own, and drop these entries.
  let lk {.used.} = acquire(repo)
  let meta = loadManifestMeta(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  let entries = meta.entries
  if entries.len == 0:
    if splitRecordIds(repo).len > 0:
      nvRaise("FATAL: no records this identity can open.\n" &
              "  Refusing to treat the vault as empty (unread wrap groups stay).")
    # Still drop the data keys this identity can open. Returning here
    # used to leave a key file behind for entries that no longer exist.
    for path in keyFiles(repo, cfg):
      try:
        discard decryptToString(cfg, path, false)
        removeFile(path)
      except CatchableError:
        discard
    nvEcho("vault is empty")
    return

  banner("Sealing vault ...")

  # Verify all plaintext files exist first
  for e in entries:
    let src = resolvePath(cfg, e.path)
    if not fileExists(src):
      stderr.writeLine &"FATAL: plaintext missing: {src}"
      nvRaise("  Run 'nimvault unseal' first, or 'nimvault rm' to remove the entry.")
    assertReadPath(cfg, repo, src)

  let currentKey = sealKey(cfg)
  # No recorded key means a v4 or older manifest: seal everything once to
  # establish one, rather than trusting hashes written under unknown settings.
  let resealAll = force or meta.sealKey.len == 0 or meta.sealKey != currentKey

  var plainHashes = initTable[string, string]()
  var todo: seq[VaultEntry] = @[]
  var keptIds = initHashSet[string]()
  for e in entries:
    let plainPath = resolvePath(cfg, e.path)
    let ph = sha256sum(plainPath)
    plainHashes[e.id] = ph
    if resealAll or e.contentHash.len == 0 or e.contentHash != ph:
      todo.add(e)
      continue
    # Plaintext matches. The blob still has to be present and intact, or a
    # deleted or corrupted blob would survive as a skipped entry.
    let blob = resolveBlob(repo, cfg, e.id, e.hash)
    if blob.len == 0 or not fileExists(blob) or
       e.hash.len == 0 or sha256sum(blob) != e.hash:
      todo.add(e)
    else:
      keptIds.incl(e.id)

  # Format v6: each payload is encrypted under its own data key, and the data
  # keys live in one small file encrypted to the recipients. Adding a machine
  # or rotating a recipient key then rewrites that file and leaves every
  # payload alone, instead of re-encrypting the whole vault.
  #
  # A fresh key per re-encryption rather than a reused one: the key file is
  # small, and a key that never outlives the bytes it protects is the cheaper
  # thing to reason about.
  var deks = deksForEntries(repo, cfg, entries, meta.deks)
  var recordDeks = meta.deks
  # Which recipients may open each entry. With no `wrap` rules every entry
  # lands in one group holding the configured recipient, which is byte for
  # byte the behaviour before groups existed.
  var groupOf = initTable[string, string]()
  var recipsOf = initTable[string, seq[string]]()
  for e in entries:
    let recips = recipientsFor(cfg, e.path)
    let gid = groupId(recips)
    groupOf[e.id] = gid
    recipsOf[gid] = recips

  # New ciphertext goes to `<id>.gpg.pending`. The live blob stays until the
  # record that names the new bytes and the new data key is durable. A crash
  # or a refused record write must not replace the blob the old record still
  # vouches for. `rename` is not `renameOver`: a failed rename must leave the
  # pending file in place once the record names it.
  var pendingHash = initTable[string, string]()
  var pendingPaths: seq[string] = @[]
  var recordsCommitted = false
  try:
    for e in todo:
      let inPath = resolvePath(cfg, e.path)
      let pend = crypto.blobPath(repo, cfg, e.id) & ".pending"
      let key = newDek(cfg)
      encryptWithDek(cfg, key, inPath, pend)
      pendingPaths.add(pend)
      pendingHash[e.id] = sha256sum(pend)
      deks[e.id] = key
      recordDeks[e.id] = key
      syncPath(pend)
      nvEcho(&"  {e.path}")

    # Drop keys for entries that are gone, so the file does not accumulate the
    # means to read blobs nobody kept.
    var live = initHashSet[string]()
    for e in entries:
      live.incl(e.id)
    var stale: seq[string] = @[]
    for id in deks.keys:
      if id notin live:
        stale.add(id)
    for id in stale:
      deks.del(id)

    # Blob + plaintext content hashes; v4 manifest enables fast status without GPG
    var hashedEntries: seq[VaultEntry] = @[]
    for e in entries:
      if e.id in keptIds:
        hashedEntries.add(e)
      elif pendingHash.hasKey(e.id):
        hashedEntries.add((e.id, e.path, pendingHash[e.id], e.kind,
                           plainHashes.getOrDefault(e.id)))
      else:
        let blobPath = resolveBlob(repo, cfg, e.id, e.hash)
        hashedEntries.add((e.id, e.path, sha256sum(blobPath), e.kind,
                           plainHashes.getOrDefault(e.id)))

    # The manifest is encrypted and signed, so writing it is itself a rewrite:
    # a seal that changed nothing would still leave one modified file behind and
    # a fresh signature over identical content. Leave it alone when it already
    # says exactly this.
    if todo.len == 0 and meta.sealKey == currentKey and hashedEntries == entries:
      if stale.len > 0:
        saveDeksGrouped(repo, cfg, deks, groupOf, recipsOf)
      nvEcho(&"\nNothing to seal; {entries.len} file(s) already current.")
      return

    saveManifest(repo, hashedEntries, cfg, currentKey, envelope = true,
                 knownDeks = recordDeks, haveDeks = true)
    recordsCommitted = true
    for e in todo:
      let pend = crypto.blobPath(repo, cfg, e.id) & ".pending"
      let dest = crypto.blobPath(repo, cfg, e.id)
      if fileExists(pend):
        publishPending(pend, dest)
        syncPath(dest)
    if todo.len > 0:
      syncParentDir(crypto.blobPath(repo, cfg, todo[0].id))
    saveDeksGrouped(repo, cfg, deks, groupOf, recipsOf)
  except CatchableError:
    if not recordsCommitted:
      discardPendingUnlessRecorded(repo, cfg, pendingPaths)
    raise
  if keptIds.len > 0:
    nvEcho(&"\nSealed {todo.len} file(s), {keptIds.len} unchanged.")
  else:
    nvEcho(&"\nSealed {todo.len} file(s).")

proc add*(repo, path: string, cfg: GpgConfig, noGitignore = false) =
  ## Add a file by its target path.
  # Mutating command: hold the vault lock so a concurrent nimvault
  # cannot read this manifest, write its own, and drop these entries.
  let lk {.used.} = acquire(repo)
  var absPath = if path.isAbsolute:
    path
  elif path.startsWith("~/"):
    expandHome(path)
  elif cfg.root.len > 0:
    cfg.root / path
  else:
    expandHome(path)
  if not absPath.isAbsolute:
    absPath = absolutePath(absPath)
  if not isPathSafe(cfg, storePath(cfg, absPath, repo)):
    nvRaise(&"FATAL: refusing path outside the vault root: {absPath}")

  if not fileExists(absPath):
    if dirExists(absPath):
      nvRaise(&"FATAL: {absPath} is a directory. Use 'nimvault add-dir'.")
    nvRaise(&"FATAL: file not found: {absPath}")

  banner(&"Adding {storePath(cfg, absPath, repo)} to vault ...")
  ensureVaultDir(repo)
  let meta = loadManifestMeta(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  var entries = meta.entries
  var existing = initHashSet[string]()
  for e in entries:
    existing.incl(e.id)
  var deks = deksForEntries(repo, cfg, entries, meta.deks)
  addOneFile(repo, absPath, cfg, noGitignore, entries, deks)
  var recordDeks = meta.deks
  for e in entries:
    if e.id notin existing and e.id in deks:
      recordDeks[e.id] = deks[e.id]
  persistDeks(repo, cfg, deks, entries)
  saveManifestKeep(repo, entries, cfg, envelope = true,
                   knownDeks = recordDeks, haveDeks = true)
  let last = entries[^1]
  nvEcho(&"  id:   {last.id}")
  nvEcho(&"  path: {last.path}")
  nvEcho(&"  blob: .vault/{last.id}{cfg.blobExt}")

proc addDir*(repo, dirPath: string, cfg: GpgConfig, noGitignore = false) =
  ## Add a directory recursively to the vault.
  # Mutating command: hold the vault lock so a concurrent nimvault
  # cannot read this manifest, write its own, and drop these entries.
  let lk {.used.} = acquire(repo)
  let absDirPath = if dirPath.isAbsolute:
    dirPath
  elif dirPath.startsWith("~/"):
    expandHome(dirPath)
  elif cfg.root.len > 0:
    cfg.root / dirPath
  else:
    expandHome(dirPath)

  if not dirExists(absDirPath):
    nvRaise(&"FATAL: directory not found: {absDirPath}")

  # Collect all files in the directory tree (recursive)
  var filesToAdd: seq[string] = @[]

  proc walkDirRecursive(dir: string) =
    for kind, path in walkDir(dir, relative = false):
      case kind
      of pcFile:
        filesToAdd.add(path)
      of pcDir:
        walkDirRecursive(path)
      of pcLinkToFile, pcLinkToDir:
        nvRaise(&"FATAL: refusing symlink in add-dir: {path}")

  walkDirRecursive(absDirPath)

  if filesToAdd.len == 0:
    nvRaise(&"FATAL: directory is empty: {absDirPath}")

  banner(&"Adding directory {dirPath} ({filesToAdd.len} files) to vault ...")
  ensureVaultDir(repo)

  let meta = loadManifestMeta(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  var entries = meta.entries
  var existing = initHashSet[string]()
  for e in entries:
    existing.incl(e.id)
  var deks = deksForEntries(repo, cfg, entries, meta.deks)
  for filePath in filesToAdd:
    addOneFile(repo, filePath, cfg, noGitignore, entries, deks)

  var recordDeks = meta.deks
  for e in entries:
    if e.id notin existing and e.id in deks:
      recordDeks[e.id] = deks[e.id]
  persistDeks(repo, cfg, deks, entries)
  saveManifestKeep(repo, entries, cfg, envelope = true,
                   knownDeks = recordDeks, haveDeks = true)
  nvEcho(&"\nAdded {filesToAdd.len} file(s) from directory.")

proc remove*(repo, path: string, cfg: GpgConfig) =
  # Mutating command: hold the vault lock so a concurrent nimvault
  # cannot read this manifest, write its own, and drop these entries.
  let lk {.used.} = acquire(repo)
  let absPath = if path.isAbsolute:
    path
  elif path.startsWith("~/"):
    expandHome(path)
  elif cfg.root.len > 0:
    cfg.root / path
  else:
    expandHome(path)

  let meta = loadManifestMeta(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  var entries = meta.entries
  var found = false
  var newEntries: seq[VaultEntry] = @[]
  var deks = deksForEntries(repo, cfg, entries, meta.deks)
  var droppedId = ""
  for e in entries:
    if resolvePath(cfg, e.path) == absPath:
      found = true
      droppedId = e.id
      let blobPath = findBlob(repo, cfg, e.id)
      if fileExists(blobPath):
        removeFile(blobPath)
        nvEcho(&"  Removed .vault/{e.id}{cfg.blobExt}")
      let pend = crypto.blobPath(repo, cfg, e.id) & ".pending"
      if fileExists(pend):
        removeFile(pend)
      deks.del(e.id)
      nvEcho(&"  Removed manifest entry: {e.path}")
    else:
      newEntries.add(e)

  if not found:
    nvRaise(&"Not in vault: {path}")

  var recordDeks = meta.deks
  if droppedId in recordDeks:
    recordDeks.del(droppedId)
  persistDeks(repo, cfg, deks, newEntries)
  saveManifestKeep(repo, newEntries, cfg,
                   knownDeks = recordDeks, haveDeks = true)
  dropEntryRecord(repo, cfg, droppedId)
  nvEcho("  (local plaintext file NOT deleted)")

proc get*(repo, path: string, cfg: GpgConfig, allowUnsigned = false): string =
  ## Decrypt one tracked entry and return its plaintext. Nothing is written to
  ## disk and nothing else in the vault is touched.
  ##
  ## `unseal` is all-or-nothing and materialises every entry, which is the wrong
  ## shape for a caller that wants one credential: a forced-command SSH gate
  ## serving a single allowlisted secret, a service reading one token at start
  ## up. Without this those callers shell out to gpg against the blobs directly,
  ## which works but puts secrets outside anything `list`, `status` or `scan`
  ## can see.
  ##
  ## The same checks `unseal` performs still apply. A caller asking for one
  ## entry has no less need of a path-safety check and an integrity check than
  ## one asking for all of them.
  ##
  ## Holds the vault lock: `resolveBlob` may rename a pending blob over the
  ## live one, which a seal in progress may be publishing too.
  let lk {.used.} = acquire(repo)
  let requireSig = not allowUnsigned
  let meta = loadManifestMeta(repo, verifySig = requireSig, cfg = cfg,
                              checkPresent = true)
  let entries = meta.entries
  let deks = deksForEntries(repo, cfg, entries, meta.deks)

  let absPath = if path.isAbsolute:
    path
  elif path.startsWith("~/"):
    expandHome(path)
  elif cfg.root.len > 0:
    cfg.root / path
  else:
    expandHome(path)

  for e in entries:
    if resolvePath(cfg, e.path) != absPath:
      continue

    if not isPathSafe(cfg, e.path):
      stderr.writeLine &"FATAL: unsafe path in manifest: {e.path}"
      nvRaise("  Possible directory traversal attack.")

    var snap = snapshotBlob(repo, cfg, e, requireSig)
    try:
      for ch in e.id:
        if ch notin {'0'..'9', 'a'..'f', 'A'..'F'}:
          nvRaise(&"FATAL: malformed entry id: {e.id}")
      if deks.hasKey(e.id):
        # v6: no in-band signature to verify, exactly as for age. Authenticity
        # came from the signed manifest and the digest checked in snapshotBlob.
        # Decrypt to memory. A file under the runtime directory is plaintext
        # another uid can read for as long as the process is decrypting.
        let plain = decryptWithDekBytesToString(cfg, deks[e.id], snap.cipher)
        return plain
      let plain = decryptBytesToString(cfg, snap.cipher, e.path,
                                       verifySig = requireSig,
                                       checkPresent = true)
      return plain
    finally:
      discardSnapshot(snap)

  nvRaise(&"Not in vault: {path}")

proc renameAt(src, dest: cstring): cint {.importc: "rename", header: "<stdio.h>".}

proc safeMovePath(oldAbs, newAbs: string) =
  ## Move without `moveFile`'s cross-device copy-through-symlink fallback.
  if symlinkExists(oldAbs):
    nvRaise(&"FATAL: refusing source symlink: {oldAbs}")
  if symlinkExists(newAbs):
    nvRaise(&"FATAL: refusing destination symlink: {newAbs}")
  createDir(newAbs.parentDir)
  if renameAt(oldAbs.cstring, newAbs.cstring) == 0:
    return
  if posix.errno != posix.EXDEV:
    nvRaise(&"FATAL: could not move {oldAbs} -> {newAbs}")
  # `copyFile` creates the copy with the process umask, which left a 0600
  # secret 0644. Create it owner-only, then give it the source's mode.
  let tmp = newAbs.parentDir / (".nimvault-mv-" & genId() & ".tmp")
  try:
    withPrivateUmask:
      copyFile(oldAbs, tmp)
    setFilePermissions(tmp, getFilePermissions(oldAbs))
  except CatchableError:
    shredFile(tmp)
    raise
  renameOver(tmp, newAbs)
  shredFile(oldAbs)

proc move*(repo, oldPath, newPath: string, cfg: GpgConfig) =
  # Mutating command: hold the vault lock so a concurrent nimvault
  # cannot read this manifest, write its own, and drop these entries.
  let lk {.used.} = acquire(repo)
  let oldAbs = if oldPath.isAbsolute:
    oldPath
  elif oldPath.startsWith("~/"):
    expandHome(oldPath)
  elif cfg.root.len > 0:
    cfg.root / oldPath
  else:
    expandHome(oldPath)

  let newAbs = if newPath.isAbsolute:
    newPath
  elif newPath.startsWith("~/"):
    expandHome(newPath)
  elif cfg.root.len > 0:
    cfg.root / newPath
  else:
    expandHome(newPath)

  # `rename` follows a directory symlink above the source as readily as one
  # above the destination, and would move a file from outside the root.
  assertAncestorsContained(cfg, repo, oldAbs, "move")
  let newStored = storePath(cfg, newAbs, repo)
  if not isPathSafe(cfg, newStored):
    nvRaise(&"FATAL: refusing path outside the vault root: {newAbs}")
  assertStoreable(newStored)
  assertStoreable(newAbs)
  assertWritePath(cfg, repo, newAbs)
  if symlinkExists(newAbs):
    nvRaise(&"FATAL: refusing destination symlink: {newAbs}")

  let meta = loadManifestMeta(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  var entries = meta.entries
  var idx = -1
  for i, e in entries:
    if resolvePath(cfg, e.path) == oldAbs:
      idx = i
      break
  if idx < 0:
    nvRaise(&"Not in vault: {oldPath}")

  let keyOnly = keyFileOnlyDekEntries(repo, cfg, @[entries[idx]], meta.deks)
  if keyOnly.len > 0:
    refuseUnsignedDekResign(keyOnly, "move")
  if fileExists(oldAbs) or symlinkExists(oldAbs):
    safeMovePath(oldAbs, newAbs)
    nvEcho(&"  Moved {entries[idx].path} -> {newStored}")
  elif fileExists(newAbs):
    nvEcho(&"  File already at {newStored}")
  else:
    nvRaise(&"FATAL: file not found at {oldAbs} or {newAbs}")
  entries[idx].path = newStored
  persistDeks(repo, cfg, deksForEntries(repo, cfg, entries, meta.deks), entries)
  saveManifestKeep(repo, entries, cfg,
                   knownDeks = meta.deks, haveDeks = true)
  nvEcho(&"  Updated manifest (blob unchanged)")

proc listReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly list (no terminal styling). Used by CLI and C ABI.
  let entries = loadManifest(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  if entries.len == 0:
    return "vault is empty\n"
  for e in entries:
    result.add &"  {e.id}  {e.path}\n"

proc list*(repo: string, cfg: GpgConfig) =
  stdout.write listReport(repo, cfg)

const BinaryExts = [
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
  ".pdf", ".epub", ".mobi",
  ".gz", ".zip", ".tar", ".bz2", ".xz", ".7z", ".zst",
  ".so", ".dylib", ".dll", ".o", ".a", ".bin", ".exe", ".rlib", ".wasm", ".elf",
  ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".m4a", ".webm", ".mov", ".avi",
  ".ttf", ".otf", ".woff", ".woff2", ".eot",
  ".sqlite", ".sqlite3", ".db", ".gpg", ".age",
]

const AlwaysSkipDirs = [
  ".git", ".vault", ".cache", ".tmpclaude", ".pixi", ".venv", "venv",
  "target", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache",
  ".pytest_cache", ".tox", "build", "dist",
]

# Claude Code / Codex runtime state. These names are common in a repository
# (`tmp`, `log`, `projects`), so they only match under the tool's own directory.
const AgentStateDirs = [
  "projects", "cache", "plugins", "sessions", "file-history", "backups",
  "tasks", "plans", "teams", "todos", "debug", "downloads", "telemetry",
  "paste-cache", "session-env", "shell-snapshots", "shell_snapshots",
  "memories", "log", "logs", "tmp", ".tmp",
]

const SkipFileNames = [
  # Claude Code's own OAuth token file; it is managed natively and not a
  # vault target.
  ".credentials.json",
]

type SecretHit = tuple[file, rule: string, line: int, bytes: int]

proc compileRules(): seq[(string, Regex)] =
  ## Returns (rule-name, compiled-regex) pairs. Order matters: more specific
  ## prefixes first so the Anthropic match wins against the generic sk- rule.
  @[
    ("anthropic-api-key", re(r"sk-ant-[A-Za-z0-9_\-]{24,}")),
    ("context7-api-key", re(r"ctx7sk-[a-f0-9\-]{20,}")),
    ("openai-api-key", re(r"sk-[A-Za-z0-9]{20,}")),
    ("github-pat", re(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("gitlab-pat", re(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("slack-token", re(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("aws-access-key", re(r"(AKIA|ASIA)[0-9A-Z]{16}")),
    ("ssh-private-key", re(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
  ]

proc componentSkipped(path: string): bool =
  ## Dependency and tool directories. A repository directory named `tmp` is
  ## not skipped: that name is only special under `.claude` or `.codex`.
  var prev = ""
  for part in path.split(DirSep):
    if part.len == 0: continue
    if part in AlwaysSkipDirs: return true
    if prev in [".claude", ".codex"] and part in AgentStateDirs: return true
    prev = part
  false

proc isBinaryExt(path: string): bool =
  let ext = splitFile(path).ext.toLowerAscii
  for b in BinaryExts:
    if ext == b: return true
  false

proc isSkippedFile(path: string): bool =
  let base = lastPathPart(path)
  for s in SkipFileNames:
    if base == s: return true
  false

proc scanText(label, content: string, nbytes: int,
               rules: seq[(string, Regex)]): seq[SecretHit] =
  var lineNo = 0
  for line in content.splitLines:
    inc lineNo
    # Short-circuit on extremely long lines (minified JS, base64 blobs)
    if line.len > 2000: continue
    for (name, rx) in rules:
      if line.contains(rx):
        result.add((label, name, lineNo, nbytes))
        break  # one hit per line is enough

proc scanFile(path: string, rules: seq[(string, Regex)]): seq[SecretHit] =
  if not fileExists(path): return
  let nbytes = int(getFileSize(path))
  if nbytes > 2_000_000: return  # skip very large files
  var content: string
  try:
    content = readFile(path)
  except IOError:
    return
  result = scanText(path, content, nbytes, rules)

proc canonicalPath(path: string): string =
  ## `path` with the symlinks in its directories resolved, so a vaulted file
  ## and the same file named through another spelling of a directory match.
  let abs = normalizedPath(absolutePath(path))
  try:
    resolvedParentForWrite(abs) / abs.extractFilename
  except CatchableError:
    abs

proc loadVaulted(repo: string, cfg: GpgConfig): HashSet[string] =
  ## Absolute paths of vaulted files, as written and resolved. The worktree
  ## walk skips these, so the records are verified: an unsigned record would
  ## otherwise choose which files go unscanned. The stored path itself is not
  ## added. Relative to another root it names a different file in this tree.
  result = initHashSet[string]()
  if repo.len == 0:
    return
  for e in loadManifest(repo, verifySig = recordsNeedSig(cfg), cfg = cfg):
    let abs = normalizedPath(resolvePath(cfg, e.path))
    result.incl(abs)
    result.incl(canonicalPath(abs))

proc isVaulted(vaulted: HashSet[string], path: string): bool =
  normalizedPath(path) in vaulted or canonicalPath(path) in vaulted

proc scan*(repo: string, target: string, cfg: GpgConfig) =
  ## Walk `target` (file or dir) and flag any file containing a secret
  ## pattern that is NOT already in the vault.
  let abs = if target.isAbsolute: target
            elif target.startsWith("~/"): expandHome(target)
            elif target.len == 0: repo
            else: absolutePath(target)

  if not fileExists(abs) and not dirExists(abs):
    nvRaise(&"FATAL: not a file or directory: {abs}")

  let vaulted = loadVaulted(repo, cfg)
  let rules = compileRules()

  var files: seq[string]
  if fileExists(abs):
    files.add(abs)
  else:
    for path in walkDirRec(abs, yieldFilter = {pcFile},
                           skipSpecial = true, relative = false):
      if componentSkipped(path): continue
      files.add(path)

  var hits: seq[SecretHit]
  var scanned = 0
  for f in files:
    if componentSkipped(f): continue
    if isVaulted(vaulted, f): continue
    if isBinaryExt(f): continue
    if isSkippedFile(f): continue
    inc scanned
    hits.add(scanFile(f, rules))

  if hits.len == 0:
    if not nvQuiet:
      echo &"scanned {scanned} file(s); no unvaulted secrets found"
    else:
      nvRaise(&"scanned {scanned} file(s); no unvaulted secrets found")
    return

  if not nvQuiet:
    banner(&"Unvaulted secrets found ({hits.len})")
    for h in hits:
      styledEcho fgRed, &"  [{h.rule}] {h.file}:{h.line} bytes={h.bytes}"
    echo &"\nscanned {scanned} file(s); {hits.len} potential secret(s) in {hits.len} line(s)."
    echo "Fix: nimvault add <file> && nimvault seal, OR rotate+replace the literal."
  var report = &"Unvaulted secrets found ({hits.len})\n"
  for h in hits:
    report.add &"  [{h.rule}] {h.file}:{h.line} bytes={h.bytes}\n"
  report.add &"\nscanned {scanned} file(s); {hits.len} potential secret(s).\n"
  report.add "Fix: nimvault add <file> && nimvault seal, OR rotate+replace the literal."
  nvRaise(report)

proc reportHits(hits: seq[SecretHit], scanned: int) =
  if hits.len == 0:
    if not nvQuiet:
      echo &"scanned {scanned} file(s); no unvaulted secrets found"
    else:
      nvRaise(&"scanned {scanned} file(s); no unvaulted secrets found")
    return
  if not nvQuiet:
    banner(&"Unvaulted secrets found ({hits.len})")
    for h in hits:
      styledEcho fgRed, &"  [{h.rule}] {h.file}:{h.line} bytes={h.bytes}"
    echo &"\nscanned {scanned} file(s); {hits.len} potential secret(s) in {hits.len} line(s)."
    echo "Fix: nimvault add <file> && nimvault seal, OR rotate+replace the literal."
  var report = &"Unvaulted secrets found ({hits.len})\n"
  for h in hits:
    report.add &"  [{h.rule}] {h.file}:{h.line} bytes={h.bytes}\n"
  report.add &"\nscanned {scanned} file(s); {hits.len} potential secret(s).\n"
  report.add "Fix: nimvault add <file> && nimvault seal, OR rotate+replace the literal."
  nvRaise(report)

proc gitCapture(repo: string, args: seq[string]): tuple[outp: string, code: int] =
  let p = startProcess("git",
    args = @["-C", repo, "--no-pager"] & args,
    options = {poUsePath})
  result.outp = p.outputStream.readAll()
  discard p.errorStream.readAll()
  result.code = p.waitForExit()
  p.close()

proc gitMust(repo: string, args: seq[string]): string =
  let got = gitCapture(repo, args)
  if got.code != 0:
    nvRaise("FATAL: git " & args.join(" ") & " failed")
  got.outp

proc splitZ(s: string): seq[string] =
  for part in s.split('\0'):
    if part.len > 0:
      result.add(part)

proc isHexSha(s: string): bool =
  if s.len == 0: return false
  for c in s:
    if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
      return false
  true

proc revCharsOk(rev: string): bool =
  ## A revision reaches git argv. Hex and a single `..` range only, so a
  ## value that looks like an option cannot change what git does.
  if rev.len == 0 or rev[0] == '-' or rev[0] == '.':
    return false
  var dots = 0
  for c in rev:
    if c == '.':
      inc dots
    elif c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
      return false
  dots == 0 or dots == 2

proc remoteNameOk(name: string): bool =
  ## A remote name reaches git as `--remotes=<name>`. Letters, digits and
  ## `._-/` only, so it cannot widen into a glob or another option.
  if name.len == 0 or name[0] in {'-', '.', '/'} or ".." in name:
    return false
  for c in name:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9', '.', '_', '-', '/'}:
      return false
  true

proc commitsIn(gitRepo, rev: string, remote = ""): seq[string] =
  ## Commits in `rev`, oldest first. With `remote`, commits already reachable
  ## from that remote's tracking refs are left out: they were scanned, or
  ## let through, when they were pushed.
  if not revCharsOk(rev):
    nvRaise("FATAL: refusing revision")
  var ends: seq[string]
  if ".." in rev:
    ends = rev.split("..")
    if ends.len != 2 or not isHexSha(ends[0]) or not isHexSha(ends[1]):
      nvRaise("FATAL: refusing revision")
  elif not isHexSha(rev):
    nvRaise("FATAL: refusing revision")
  else:
    ends = @[rev]
  if remote.len > 0 and not remoteNameOk(remote):
    nvRaise(&"FATAL: refusing remote name: {remote}")
  for sha in ends:
    if gitCapture(gitRepo, @["cat-file", "-e", sha & "^{commit}"]).code != 0:
      nvRaise(&"FATAL: commit {sha} is not in this repository.\n" &
              "  The remote has commits this clone has not fetched. Run " &
              "'git fetch', merge or rebase onto them, and push again.")
  var args = @["rev-list", "--reverse", rev]
  if remote.len > 0:
    args.add(@["--not", "--remotes=" & remote])
  let listed = gitMust(gitRepo, args)
  for line in listed.splitLines:
    let s = line.strip()
    if s.len == 0: continue
    if not isHexSha(s):
      nvRaise("FATAL: refusing revision")
    result.add(s)

proc noteHit(hits: var seq[SecretHit], seen: var HashSet[string], hit: SecretHit) =
  let key = hit.file & "\t" & hit.rule & "\t" & $hit.line
  if key in seen: return
  seen.incl(key)
  hits.add(hit)

proc considerGitBlob(gitRepo, rel, spec: string, vaulted: HashSet[string],
                     rules: seq[(string, Regex)],
                     hits: var seq[SecretHit], seen: var HashSet[string],
                     scanned: var int) =
  ## `spec` is `:<rel>` or `<sha>:<rel>` and goes to git after `--`, so a
  ## name that starts with `-` or holds a newline is still just a name.
  ##
  ## A vaulted path is reported whatever its bytes are. The worktree walk
  ## skips it because unsealed plaintext belongs on disk; in the index or in
  ## a commit it is that plaintext on its way into git history. Its bytes are
  ## still matched against the patterns, so the report names what leaked.
  if rel.len == 0:
    return
  if rel == ".vault" or rel.startsWith(".vault/") or
     rel == ".git" or rel.startsWith(".git/"):
    return
  let abs = normalizedPath(gitRepo / rel)
  let inVault = isVaulted(vaulted, abs)
  if not inVault and isBinaryExt(rel):
    return
  var nbytes = -1
  let sz = gitCapture(gitRepo, @["cat-file", "-s", "--", spec])
  if sz.code == 0:
    try:
      nbytes = parseInt(sz.outp.strip)
    except ValueError:
      discard
  if inVault:
    noteHit(hits, seen, (abs, "vault-plaintext", 1, max(nbytes, 0)))
    inc scanned
  if nbytes < 0 or nbytes > 2_000_000 or isBinaryExt(rel):
    return
  let blob = gitCapture(gitRepo, @["cat-file", "blob", "--", spec])
  if blob.code != 0 or '\0' in blob.outp:
    return
  if not inVault:
    inc scanned
  for hit in scanText(abs, blob.outp, nbytes, rules):
    noteHit(hits, seen, hit)

proc scanCached*(repo: string, cfg: GpgConfig, gitRepo: string) =
  ## Scan the index, not the worktree. A staged secret whose worktree copy
  ## was edited back, and a vaulted file forced into the index, are both
  ## invisible to a walk of the working tree.
  if gitRepo.len == 0 or not dirExists(gitRepo):
    nvRaise(&"FATAL: not a git repository: {gitRepo}")
  let vaulted = loadVaulted(repo, cfg)
  let rules = compileRules()
  let listed = gitMust(gitRepo, @["diff", "--cached", "--name-only",
                                  "--diff-filter=ACMRT", "-z"])
  var hits: seq[SecretHit] = @[]
  var seen = initHashSet[string]()
  var scanned = 0
  for rel in splitZ(listed):
    considerGitBlob(gitRepo, rel, ":" & rel, vaulted, rules, hits, seen, scanned)
  reportHits(hits, scanned)

proc scanRev*(repo: string, cfg: GpgConfig, gitRepo, rev: string,
              remote = "") =
  ## Scan blobs introduced by `rev` (`A..B` or one commit and its ancestors).
  ## The diff of the two tips misses a secret that was added and removed
  ## again inside the range. `remote` drops commits that remote already has.
  if gitRepo.len == 0 or not dirExists(gitRepo):
    nvRaise(&"FATAL: not a git repository: {gitRepo}")
  let vaulted = loadVaulted(repo, cfg)
  let rules = compileRules()
  var hits: seq[SecretHit] = @[]
  var seen = initHashSet[string]()
  var scanned = 0
  for commit in commitsIn(gitRepo, rev, remote):
    let listed = gitMust(gitRepo, @[
      "diff-tree", "--root", "-m", "-r", "--no-commit-id", "--name-only",
      "--diff-filter=ACMRT", "-z", commit])
    for rel in splitZ(listed):
      considerGitBlob(gitRepo, rel, commit & ":" & rel, vaulted, rules,
                      hits, seen, scanned)
  reportHits(hits, scanned)

proc statusReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly status (no colors). Fast path uses contentHash when present.
  ## Holds the vault lock for the pending-blob rename in `resolveBlob`.
  let lk {.used.} = acquire(repo)
  let entries = loadManifest(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  if entries.len == 0:
    return "vault is empty\n"

  result.add "Vault status\n"
  var needDecrypt: seq[VaultEntry] = @[]
  for e in entries:
    let localPath = resolvePath(cfg, e.path)
    let blobPath = resolveBlob(repo, cfg, e.id, e.hash)

    if not fileExists(localPath):
      result.add &"  [missing]   {e.path}\n"
      continue

    if not fileExists(blobPath):
      result.add &"  [no-blob]   {e.path}\n"
      continue

    let localHash = sha256sum(localPath)
    if e.contentHash.len > 0:
      if localHash == e.contentHash:
        result.add &"  [in-sync]   {e.path}\n"
      else:
        result.add &"  [modified]  {e.path}\n"
      continue

    needDecrypt.add(e)

  if needDecrypt.len == 0:
    return

  let batchSize = gpgParallelism()
  let work = privateWorkDir()
  type StRow = tuple[entry: VaultEntry, localHash, tmpPath, status: string, code: int]
  var rows: seq[StRow] = @[]
  try:
    withPrivateUmask:
      for batchStart in countup(0, needDecrypt.high, batchSize):
        let batchEnd = min(batchStart + batchSize - 1, needDecrypt.high)
        var procs: seq[(VaultEntry, string, string, Process)] = @[]
        for i in batchStart .. batchEnd:
          let e = needDecrypt[i]
          let localPath = resolvePath(cfg, e.path)
          let localHash = sha256sum(localPath)
          let blobPath = resolveBlob(repo, cfg, e.id, e.hash)
          let tmpPath = work / e.id
          let p = decryptProcess(cfg, blobPath, tmpPath)
          procs.add((e, localHash, tmpPath, p))
        for (e, localHash, tmpPath, p) in procs:
          discard p.outputStream.readAll()
          let status = p.errorStream.readAll()
          let code = p.waitForExit()
          p.close()
          rows.add((e, localHash, tmpPath, status, code))

    for r in rows:
      if r.code != 0:
        result.add &"  [error]     {r.entry.path}\n"
        continue
      let vaultHash = sha256sum(r.tmpPath)
      if r.localHash == vaultHash:
        result.add &"  [in-sync]   {r.entry.path}\n"
      else:
        result.add &"  [modified]  {r.entry.path}\n"
  finally:
    discardPrivate(work)

proc rotate*(repo: string, cfg: GpgConfig, rekey = false) =
  ## Re-wrap the data keys to the current recipients, or re-encrypt everything.
  ##
  ## These are different operations, and the difference is the reason v6 exists,
  ## so they are separate flags rather than one command that guesses.
  ##
  ## Default: the data-key file is decrypted and written back to whoever
  ## `.vault/config` now names. Every payload is untouched, so adding a machine
  ## costs one small file instead of the whole vault. What that gives is
  ## rotation of the *wrapping*: a recipient key that should no longer open the
  ## vault stops being able to.
  ##
  ## `rekey`: every payload is re-encrypted under a fresh data key. Only that
  ## answers a suspected compromise of a data key or of the plaintext, because
  ## rewrapping leaves the old ciphertext openable by whoever already holds the
  ## old key (Everspaugh et al., CRYPTO 2017,
  ## doi:10.1007/978-3-319-63697-9_4). Churn is the intent, so it deliberately
  ## bypasses the incremental skip.
  if rekey:
    banner("Rekeying vault ...")
    seal(repo, cfg, force = true)
    nvEcho("Every payload re-encrypted under a fresh data key.")
    return

  banner("Rewrapping data keys ...")
  let lk {.used.} = acquire(repo)
  let meta = loadManifestMeta(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  let entries = meta.entries
  if entries.len == 0:
    if splitRecordIds(repo).len > 0:
      nvRaise("FATAL: no records this identity can open.\n" &
              "  Refusing to treat the vault as empty (unread wrap groups stay).")
    nvEcho("vault is empty")
    return
  let keyOnly = keyFileOnlyDekEntries(repo, cfg, entries, meta.deks)
  if keyOnly.len > 0:
    refuseUnsignedDekResign(keyOnly, "rotate")
  let deks = deksForEntries(repo, cfg, entries, meta.deks)
  if deks.len == 0:
    nvRaise("FATAL: no data keys to rewrap; this vault predates v6.\n" &
            "  Run 'nimvault seal --force' once to move it to v6.")
  persistDeks(repo, cfg, deks, entries)
  saveSplitEntries(repo, cfg, entries, meta.deks, force = true)

  var enveloped = 0
  for e in entries:
    if deks.hasKey(e.id):
      enveloped.inc
  nvEcho(&"\nRewrapped {deks.len} data key(s); {enveloped} of {entries.len} " &
         "entries are enveloped.")
  if enveloped < entries.len:
    nvEcho("Entries without a data key still carry the recipient inside the " &
           "blob;\n  'nimvault seal --force' migrates them.")

proc orphans*(repo: string, cfg: GpgConfig): seq[string] =
  ## Blob files in `.vault/` that no manifest entry points at.
  ##
  ## Reachable when a mutation is interrupted between writing a blob and
  ## writing the manifest that names it, which the lock makes rarer but does
  ## not remove. An orphan is not merely clutter: it is a readable copy of a
  ## secret that nothing tracks, so nothing will ever rotate or remove it.
  ##
  ## A `.pending` sibling whose hash a record names is the durable ciphertext
  ## of a seal that has not renamed it yet. Removing it would strand the record.
  ## One whose record this identity cannot open is left alone: its hash is
  ## unknown here. `<id>.gpg.tmp` and `<id>.gpg.pending.tmp` are payloads a
  ## killed `add` or `seal` was still writing; no record names them.
  let entries = loadManifest(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  var opened = initHashSet[string]()
  var hashes = initHashSet[string]()
  for e in entries:
    opened.incl(e.id)
    if e.hash.len > 0:
      hashes.incl(e.hash)
  proc hasTmpRecord(id: string): bool =
    let dir = entryDir(repo)
    for ext in [cfg.blobExt, (if cfg.usesAge: ".gpg" else: ".age")]:
      if fileExists(dir / (id & ext & ".tmp")):
        return true
  var live = opened
  let recorded = splitRecordIds(repo)
  for id in recorded:
    live.incl(id)
  let dir = repo / ".vault"
  if not dirExists(dir):
    return
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.endsWith(".tmp"):
      let inner = name[0 ..< name.len - ".tmp".len]
      let blobName = if inner.endsWith(".pending"): inner[0 ..< inner.len - ".pending".len]
                     else: inner
      if (blobName.endsWith(".gpg") or blobName.endsWith(".age")) and
         isHexSha(blobName.rsplit('.', maxsplit = 1)[0]):
        result.add(path)
      continue
    if name.endsWith(".pending"):
      let id = pendingId(path)
      if id in recorded and id notin opened:
        continue
      if hasTmpRecord(id):
        continue
      if sha256sum(path) notin hashes:
        result.add(path)
      continue
    if not (name.endsWith(".gpg") or name.endsWith(".age")):
      continue
    let stem = name.rsplit('.', maxsplit = 1)[0]
    # Everything that is not a blob: the manifest, the key files, signatures.
    if stem == "manifest" or stem == KeysFileStem or
       stem.startsWith(KeysFileStem & "."):
      continue
    if stem notin live:
      result.add(path)

proc stagedPlaintext*(repo: string, cfg: GpgConfig): seq[string] =
  ## `.nimvault-<id>.tmp` files beside the entries this identity can open.
  ## `unseal` decrypts there before it verifies and renames, so a kill in
  ## between leaves plaintext that nothing tracks. Records are verified first:
  ## the directories searched are the ones they name.
  let stagedName = re"^\.nimvault-[0-9a-f]{16}\.tmp$"
  var dirs = initHashSet[string]()
  for e in loadManifest(repo, verifySig = recordsNeedSig(cfg), cfg = cfg):
    if not isPathSafe(cfg, e.path):
      stderr.writeLine &"FATAL: unsafe path in manifest: {e.path}"
      nvRaise("  Possible directory traversal attack.")
    let dest = resolvePath(cfg, e.path)
    assertWritePath(cfg, repo, dest)
    dirs.incl(dest.parentDir)
  for dir in dirs:
    if not dirExists(dir):
      continue
    for kind, path in walkDir(dir):
      if kind == pcFile and path.extractFilename.match(stagedName):
        result.add(path)

proc gc*(repo: string, cfg: GpgConfig, dryRun = false) =
  ## Remove blobs no manifest entry points at, half-written payloads, and
  ## plaintext a killed `unseal` staged beside its destination. Holding the
  ## vault lock is what makes every one of those a leftover rather than a
  ## write in progress.
  let lk {.used.} = acquire(repo)
  let found = orphans(repo, cfg)
  let staged = stagedPlaintext(repo, cfg)
  if found.len == 0 and staged.len == 0:
    nvEcho("no orphan blobs")
    return
  if found.len > 0:
    banner(&"{found.len} orphan blob(s)")
    for path in found:
      nvEcho(&"  {path.extractFilename}")
      if not dryRun:
        removeFile(path)
  if staged.len > 0:
    banner(&"{staged.len} staged plaintext file(s) from an interrupted unseal")
    for path in staged:
      nvEcho(&"  {path}")
      if not dryRun:
        shredFile(path)
  if dryRun:
    nvEcho("\ndry run; nothing removed")
  else:
    syncParentDir(repo / ".vault" / "x")
    nvEcho(&"\nRemoved {found.len} orphan blob(s) and {staged.len} staged file(s).")

type CheckResult* = tuple[problems: seq[string], checked, unopened: int]

const UnreadableRecords = "no records this identity can open; unread wrap groups remain"

proc checkVault*(repo: string, cfg: GpgConfig): CheckResult =
  ## Verify the vault is internally consistent without decrypting a payload.
  ##
  ## `status` answers a different question: it compares the *plaintext* on this
  ## machine against the manifest's `contentHash`, so it says nothing about
  ## whether each blob still matches the hash the manifest records for it. A
  ## blob committed without the manifest that vouches for it therefore looks
  ## perfectly healthy right up until an `unseal` on some other machine, where
  ## the plaintext is gone and the failure is unrecoverable rather than
  ## inconvenient.
  ##
  ## The manifest is a signed list of per-blob digests, which is a one-level
  ## Merkle construction (Merkle, CRYPTO 1987, doi:10.1007/3-540-48184-2_32):
  ## checking each leaf against it is enough to detect a blob that has drifted.
  ## The digests sit inside the encrypted records, so reading them takes the
  ## secret key that opens the records; a public key alone verifies nothing.
  ## Holds the vault lock for the pending-blob rename in `resolveBlob`.
  let lk {.used.} = acquire(repo)
  let meta = loadManifestMeta(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  let entries = meta.entries
  result.unopened = meta.unopened
  if meta.unparsed > 0:
    result.problems.add(&"{meta.unparsed} record(s) open but hold no entry " &
                        "this version can read")
    result.checked.inc
  elif entries.len == 0 and splitRecordIds(repo).len > 0:
    result.problems.add(UnreadableRecords)
    result.checked.inc
  for e in entries:
    result.checked.inc
    let blob = resolveBlob(repo, cfg, e.id, e.hash)
    if blob.len == 0:
      let live = findBlob(repo, cfg, e.id)
      let pend = crypto.blobPath(repo, cfg, e.id) & ".pending"
      if fileExists(live) or fileExists(pend):
        result.problems.add(&"blob does not match the manifest for {e.path}")
      else:
        result.problems.add(&"no blob for {e.path}")
      continue
    if not fileExists(blob):
      result.problems.add(&"no blob for {e.path}")
      continue
    if e.hash.len == 0:
      result.problems.add(&"no recorded hash for {e.path} (v1 manifest)")
      continue
    let actual = sha256sum(blob)
    if actual != e.hash:
      result.problems.add(&"blob does not match the manifest for {e.path}")
  if entries.len > 0 and meta.envelope and keyFiles(repo, cfg).len == 0 and
     not hasSplitEntries(repo):
    result.problems.add("no data-key file; this vault cannot be unsealed")
    result.checked.inc

proc checkReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly check (no colors, no exit).
  let r = checkVault(repo, cfg)
  if r.checked == 0:
    return "vault is empty\n"
  for p in r.problems:
    result.add &"  {p}\n"
  if r.unopened > 0:
    result.add &"  could not open {r.unopened} record(s) with this machine's secret keys.\n"
  if r.problems.len == 0:
    result.add &"{r.checked} entries consistent with the manifest.\n"
  else:
    result.add &"{r.problems.len} of {r.checked} entries are inconsistent.\n"

proc check*(repo: string, cfg: GpgConfig) =
  ## Terminal check. Raises when anything is inconsistent so a hook or a
  ## continuous-integration job fails rather than reporting and passing.
  let r = checkVault(repo, cfg)
  if r.checked == 0:
    nvEcho("vault is empty")
    return
  banner("Checking vault ...")
  for p in r.problems:
    stderr.writeLine &"  {p}"
  if r.unopened > 0:
    stderr.writeLine(&"  could not open {r.unopened} record(s) with this machine's secret keys")
  if UnreadableRecords in r.problems:
    nvRaise("FATAL: no record opens with the keys on this machine.\n" &
            "  check reads the blob digests from the encrypted records; import " &
            "the secret key of the recipient or of a wrap group.")
  if r.problems.len > 0:
    nvRaise(&"{r.problems.len} of {r.checked} entries are inconsistent " &
            "(seal, or restore the missing blob)")
  nvEcho(&"\n{r.checked} entries consistent with the manifest.")

proc status*(repo: string, cfg: GpgConfig) =
  ## Terminal status (colors). Delegates logic to statusReport for library reuse.
  ## Holds the vault lock for the pending-blob rename in `resolveBlob`.
  let lk {.used.} = acquire(repo)
  let entries = loadManifest(repo, verifySig = recordsNeedSig(cfg), cfg = cfg)
  if entries.len == 0:
    echo "vault is empty"
    return

  banner("Vault status")
  var needDecrypt: seq[VaultEntry] = @[]
  for e in entries:
    let localPath = resolvePath(cfg, e.path)
    let blobPath = resolveBlob(repo, cfg, e.id, e.hash)

    if not fileExists(localPath):
      styledEcho fgYellow, &"  [missing]   {e.path}"
      continue

    if not fileExists(blobPath):
      styledEcho fgRed, &"  [no-blob]   {e.path}"
      continue

    let localHash = sha256sum(localPath)
    if e.contentHash.len > 0:
      if localHash == e.contentHash:
        styledEcho fgGreen, &"  [in-sync]   {e.path}"
      else:
        styledEcho fgRed, &"  [modified]  {e.path}"
      continue

    needDecrypt.add(e)

  if needDecrypt.len == 0:
    return

  let batchSize = gpgParallelism()
  let work = privateWorkDir()
  type StRow = tuple[entry: VaultEntry, localHash, tmpPath, status: string, code: int]
  var rows: seq[StRow] = @[]
  try:
    withPrivateUmask:
      for batchStart in countup(0, needDecrypt.high, batchSize):
        let batchEnd = min(batchStart + batchSize - 1, needDecrypt.high)
        var procs: seq[(VaultEntry, string, string, Process)] = @[]
        for i in batchStart .. batchEnd:
          let e = needDecrypt[i]
          let localPath = resolvePath(cfg, e.path)
          let localHash = sha256sum(localPath)
          let blobPath = resolveBlob(repo, cfg, e.id, e.hash)
          let tmpPath = work / e.id
          let p = decryptProcess(cfg, blobPath, tmpPath)
          procs.add((e, localHash, tmpPath, p))
        for (e, localHash, tmpPath, p) in procs:
          discard p.outputStream.readAll()
          let status = p.errorStream.readAll()
          let code = p.waitForExit()
          p.close()
          rows.add((e, localHash, tmpPath, status, code))

    for r in rows:
      if r.code != 0:
        styledEcho fgRed, &"  [error]     {r.entry.path}"
        continue
      let vaultHash = sha256sum(r.tmpPath)
      if r.localHash == vaultHash:
        styledEcho fgGreen, &"  [in-sync]   {r.entry.path}"
      else:
        styledEcho fgRed, &"  [modified]  {r.entry.path}"
  finally:
    discardPrivate(work)

proc whoReport*(repo: string, cfg: GpgConfig): string =
  ## Recipients that the current wrap rules assign to each entry.
  let entries = loadManifest(repo, cfg = cfg)
  if entries.len == 0:
    return "vault is empty\n"
  for e in entries:
    let recips = recipientsFor(cfg, e.path)
    result.add &"{e.path}\t{recips.join(\",\")}\n"

proc who*(repo: string, cfg: GpgConfig) =
  stdout.write whoReport(repo, cfg)

proc editorLeftovers(path: string): seq[string] =
  ## Editor copies that sit beside a vaulted file and are not themselves entries.
  let name = path.extractFilename
  let dir = path.parentDir
  result.add(path & "~")
  result.add(dir / ("#" & name & "#"))
  result.add(dir / (".#" & name))
  for ext in [".swp", ".swo", ".swn", ".swx"]:
    result.add(dir / ("." & name & ext))

proc lockPlaintext*(repo: string, cfg: GpgConfig, allowUnsigned = false) =
  ## Remove in-sync plaintext. The vault entry stays; unseal brings it back.
  ## A modified file is refused: lock is not a way to discard unsealed edits.
  ## The blob has to match the record first. Otherwise the plaintext is the
  ## only remaining copy, and deleting it is not a lock.
  ##
  ## Records are verified as `unseal` verifies them. `--allow-unsigned`
  ## accepts missing signatures; a present one must still verify.
  ## Editor backups go only with an entry that is present and matches its
  ## recorded hash; for any other entry the record is the sole evidence that
  ## the backup is a copy of a vaulted file.
  let lk {.used.} = acquire(repo)
  let entries = loadManifest(repo, verifySig = not allowUnsigned, cfg = cfg,
                             checkPresent = true)
  if entries.len == 0:
    nvEcho("vault is empty")
    return
  for e in entries:
    if not isPathSafe(cfg, e.path):
      stderr.writeLine &"FATAL: unsafe path in manifest: {e.path}"
      nvRaise("  Possible directory traversal attack.")
    assertWritePath(cfg, repo, resolvePath(cfg, e.path))
  var doomed: seq[string] = @[]
  for e in entries:
    let local = resolvePath(cfg, e.path)
    if not fileExists(local):
      continue
    if e.contentHash.len == 0 or sha256sum(local) != e.contentHash:
      nvRaise(&"FATAL: {e.path} is modified; seal or restore it before lock")
    let blob = resolveBlob(repo, cfg, e.id, e.hash)
    if e.hash.len == 0 or not fileExists(blob) or sha256sum(blob) != e.hash:
      nvRaise(&"FATAL: {e.path} has no intact blob; refusing to delete plaintext")
    doomed.add(local)
  var removed = 0
  for local in doomed:
    shredFile(local)
    for extra in editorLeftovers(local):
      shredFile(extra)
    inc removed
    nvEcho(&"  {local}")
  nvEcho(&"\nLocked {removed} file(s); unseal to restore.")

proc initVault*(repo, recipient: string) =
  ## Write `.vault/config` so later commands have a recipient.
  ensureVaultDir(repo)
  let cfgPath = repo / ".vault" / "config"
  if fileExists(cfgPath):
    nvRaise(&"FATAL: vault already initialised: {cfgPath}")
  var rec = recipient.strip()
  if rec.len == 0:
    rec = getEnv("NIMVAULT_GPG_RECIPIENT").strip()
  if rec.len == 0:
    nvRaise("FATAL: init needs --recipient or NIMVAULT_GPG_RECIPIENT")
  if '\n' in rec or '\r' in rec:
    nvRaise("FATAL: recipient must be a single line")
  writeFile(cfgPath, &"recipient = {rec}\n")
  setFilePermissions(cfgPath, {fpUserRead, fpUserWrite})
  nvEcho(&"initialised {cfgPath}")

proc installHooks*(repo: string) =
  ## Install a pre-commit hook that scans the index and a pre-push hook that
  ## scans the commits being pushed, then runs `nimvault check`. Refuse to
  ## overwrite an existing hook. A worktree scan misses a staged secret and
  ## a secret that was committed and then deleted from the worktree.
  let hooks = repo / ".git" / "hooks"
  if not dirExists(hooks):
    nvRaise("FATAL: not a git repository (no .git/hooks)")
  let prePush = hooks / "pre-push"
  let preCommit = hooks / "pre-commit"
  if fileExists(prePush):
    nvRaise(&"FATAL: {prePush} already exists")
  if fileExists(preCommit):
    nvRaise(&"FATAL: {preCommit} already exists")
  writeFile(preCommit, """#!/bin/sh
set -eu
cd "$(git rev-parse --show-toplevel)"
exec nimvault scan --cached
""")
  # A push to a named remote skips commits its tracking refs already reach,
  # so a new branch is not judged on history that is already public. A push
  # to a bare URL has no tracking refs and scans everything the range holds.
  writeFile(prePush, """#!/bin/sh
set -eu
cd "$(git rev-parse --show-toplevel)"
remote="${1:-}"
known=""
if [ -n "$remote" ] && git config --get "remote.$remote.url" >/dev/null 2>&1; then
  known="--remote=$remote"
fi
status=0
while read -r local_ref local_sha remote_ref remote_sha; do
  case "$local_sha" in
    0000000000000000000000000000000000000000*) continue ;;
  esac
  case "$remote_sha" in
    0000000000000000000000000000000000000000*)
      nimvault scan --rev "$local_sha" $known || status=1
      ;;
    *)
      nimvault scan --rev "${remote_sha}..${local_sha}" $known || status=1
      ;;
  esac
done
nimvault check || status=1
exit "$status"
""")
  let exe = {fpUserRead, fpUserWrite, fpUserExec}
  setFilePermissions(prePush, exe)
  setFilePermissions(preCommit, exe)
  nvEcho(&"installed {prePush}")
  nvEcho(&"installed {preCommit}")

proc doctorReport*(repo: string, cfg: GpgConfig): string =
  ## What a human or CI needs to know before seal/unseal: binaries, recipient,
  ## backend, pointer, lock directory, and `check`.
  var problems: seq[string] = @[]
  let rec = if cfg.recipient.len > 0: cfg.recipient else: "(none)"
  result.add &"vault:     {repo}\n"
  result.add &"backend:   {cfg.backend}\n"
  result.add &"recipient: {rec}\n"
  if findExe("gpg").len == 0:
    problems.add("gpg is not on PATH")
  else:
    result.add "gpg:       ok\n"
  if cfg.usesAge:
    if findExe("age").len == 0 and findExe("rage").len == 0:
      problems.add("age is not on PATH")
    else:
      result.add "age:       ok\n"
    if cfg.identity.len == 0:
      problems.add("age identity is not configured")
  let enc = findManifest(repo, cfg)
  if enc.len > 0:
    result.add &"manifest:  {enc.extractFilename}\n"
    let chk = checkVault(repo, cfg)
    if chk.problems.len == 0:
      result.add &"check:     {chk.checked} entries consistent\n"
    else:
      for p in chk.problems:
        problems.add(p)
  else:
    result.add "manifest:  (none)\n"
  if problems.len > 0:
    result.add "problems:\n"
    for p in problems:
      result.add &"  {p}\n"
    nvRaise(result.strip())

proc doctor*(repo: string, cfg: GpgConfig) =
  stdout.write doctorReport(repo, cfg)

# --- Library / C ABI report wrappers (return text, raise NimvaultError, honor nvQuiet) ---

proc sealReport*(repo: string, cfg: GpgConfig): string =
  seal(repo, cfg)
  "Sealed vault entries.\n"

proc unsealReport*(repo: string, cfg: GpgConfig, allowUnsigned = false,
                   only: seq[string] = @[]): string =
  unseal(repo, cfg, allowUnsigned, only)
  "Unsealed vault entries.\n"

proc addReport*(repo, path: string, cfg: GpgConfig, noGitignore = false): string =
  add(repo, path, cfg, noGitignore)
  "Added " & path & "\n"

proc addDirReport*(repo, dirPath: string, cfg: GpgConfig, noGitignore = false): string =
  addDir(repo, dirPath, cfg, noGitignore)
  "Added directory " & dirPath & "\n"

proc removeReport*(repo, path: string, cfg: GpgConfig): string =
  remove(repo, path, cfg)
  "Removed " & path & "\n"

proc moveReport*(repo, oldPath, newPath: string, cfg: GpgConfig): string =
  move(repo, oldPath, newPath, cfg)
  "Moved " & oldPath & " -> " & newPath & "\n"

proc scanReport*(repo, target: string, cfg: GpgConfig): string =
  ## Scan without process exit. Returns report; raises only on I/O errors.
  ## If secrets found, still returns the report text (no raise) so MCP can show it.
  # Re-implement minimal: call scan logic is exit-based — run and catch
  try:
    scan(repo, target, cfg)
    result = "scanned; no unvaulted secrets found\n"
  except NimvaultError as e:
    # scan uses nvRaise for "found secrets" path if we converted quit — treat message as report
    result = e.msg & "\n"
