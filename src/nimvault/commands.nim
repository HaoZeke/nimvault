## Vault commands: seal, unseal, add, rm, mv, list, status, scan.
##
## All commands take a repo path and GpgConfig.
## Parallel GPG via startProcess with direct invocation (no shell).

import std/[os, osproc, strutils, strformat, streams, terminal, re, sets, sequtils,
            tables]
import ./gpg, ./manifest, ./crypto, ./lock, ./dek
# NimvaultError, nvRaise, nvQuiet from gpg

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

proc unseal*(repo: string, cfg: GpgConfig, allowUnsigned = false,
             only: seq[string] = @[]) =
  ## Decrypt tracked entries back to their target paths. With no selector this
  ## restores the whole vault; with one it restores only what was named.
  ##
  ## The selective form exists because all-or-nothing forces the caller to
  ## express any partial restore somewhere else. A machine that should hold a
  ## subset of the vault otherwise has to model that split in whatever tool
  ## sits above this one, which is both duplicated and invisible from here.
  let requireSig = not allowUnsigned
  let allEntries = loadManifest(repo, verifySig = requireSig, cfg = cfg)
  if allEntries.len == 0:
    nvEcho("vault is empty")
    return

  let entries = if only.len == 0: allEntries
                else: selectEntries(cfg, allEntries, only)

  if only.len == 0:
    banner("Unsealing vault ...")
  else:
    banner(&"Unsealing {entries.len} of {allEntries.len} entries ...")

  # Verify blob integrity and path safety before any decryption
  for e in entries:
    let inPath = findBlob(repo, cfg, e.id)
    if not fileExists(inPath):
      nvRaise(&"FATAL: vault blob missing: {inPath}")
    # Path traversal check
    if not isPathSafe(cfg, e.path):
      stderr.writeLine &"FATAL: unsafe path in manifest: {e.path}"
      stderr.writeLine &"  Resolved: {normalizedPath(resolvePath(cfg, e.path))}"
      nvRaise("  Possible directory traversal attack.")
    # Blob hash verification
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

  # Decrypt to temp files first (never directly to final path).
  # This prevents release of unverified plaintext: GPG streams content to
  # disk before the signature check completes, so writing to the final
  # path would expose unverified data even if we abort on BADSIG.
  # Process in batches to avoid GPG memory exhaustion (NIMVAULT_GPG_PARALLEL).
  let batchSize = gpgParallelism()
  var tmpPaths: seq[string] = @[]
  type DecryptResult = tuple[entry: VaultEntry, tmpPath, status: string,
                             code: int, enveloped: bool]
  var results: seq[DecryptResult] = @[]

  # A vault may hold both formats while a migration drains: an entry with a
  # data key is v6, one without is encrypted straight to the recipient. The
  # key file is the discriminator, and it cannot disagree with the blob because
  # a key is only ever written by the encryption that used it.
  let deks = loadDeks(repo, cfg)

  var direct: seq[VaultEntry] = @[]
  for e in entries:
    let outPath = resolvePath(cfg, e.path)
    let tmpPath = outPath & ".nimvault-tmp"
    createDir(outPath.parentDir)
    if deks.hasKey(e.id):
      tmpPaths.add(tmpPath)
      var status = ""
      var code = 0
      try:
        decryptWithDek(cfg, deks[e.id], findBlob(repo, cfg, e.id), tmpPath)
      except CatchableError as err:
        status = err.msg
        code = 1
      results.add((e, tmpPath, status, code, true))
    else:
      direct.add(e)

  for batchStart in countup(0, direct.high, batchSize):
    let batchEnd = min(batchStart + batchSize - 1, direct.high)
    var procs: seq[(VaultEntry, string, Process)] = @[]
    for i in batchStart .. batchEnd:
      let e = direct[i]
      let inPath = findBlob(repo, cfg, e.id)
      let outPath = resolvePath(cfg, e.path)
      let tmpPath = outPath & ".nimvault-tmp"
      tmpPaths.add(tmpPath)
      createDir(outPath.parentDir)
      let p = decryptProcess(cfg, inPath, tmpPath)
      procs.add((e, tmpPath, p))

    # Collect results for this batch
    for (e, tmpPath, p) in procs:
      discard p.outputStream.readAll()  # empty with -o
      let status = p.errorStream.readAll()
      let code = p.waitForExit()
      p.close()
      results.add((e, tmpPath, status, code, false))

  # Abort helper: remove all temp files before exiting
  template abortUnseal(msgs: varargs[string]) =
    for tp in tmpPaths:
      if fileExists(tp): removeFile(tp)
    var acc = ""
    for msg in msgs:
      acc.add msg & "\n"
    nvRaise(acc.strip())

  # Verify all decryption results and signatures
  for r in results:
    if r.code != 0:
      abortUnseal(&"FATAL: failed to unseal {r.entry.path}", r.status)
    # Bad signatures are always fatal (even with --allow-unsigned).
    #
    # Only gpg reports this while decrypting. age blobs carry no signature at
    # all, and their authenticity comes from the signed manifest plus the blob
    # digest already checked above; demanding GOODSIG here would reject every
    # one of them.
    if cfg.signaturesInBand and not r.enveloped and
       ("BADSIG" in r.status or "ERRSIG" in r.status):
      abortUnseal(&"FATAL: bad signature on blob for {r.entry.path}",
        "  The vault may have been tampered with.")
    # Missing signatures: fatal unless --allow-unsigned
    if cfg.signaturesInBand and not r.enveloped and requireSig and
       "GOODSIG" notin r.status:
      abortUnseal(&"FATAL: missing signature on blob for {r.entry.path}",
        "  Pass --allow-unsigned to accept unsigned vaults.")

  # All verified: atomically move temp files to final locations
  for r in results:
    let outPath = resolvePath(cfg, r.entry.path)
    moveFile(r.tmpPath, outPath)
    # Default to user-only 0600; give +x when the file is a shebang-style
    # script. Without this, unseal silently breaks hooks (e.g. the Claude
    # Code rtk-rewrite.sh PreToolUse hook would fail with "Permission
    # denied" on the next Bash call after a fresh machine was unsealed).
    var perms = {fpUserRead, fpUserWrite}
    try:
      var f: File
      if open(f, outPath, fmRead):
        defer: f.close()
        var head: array[2, char]
        let n = f.readBuffer(addr head[0], 2)
        if n == 2 and head[0] == '#' and head[1] == '!':
          perms.incl(fpUserExec)
    except IOError:
      discard
    setFilePermissions(outPath, perms)
    nvEcho(&"  {r.entry.path}")

  nvEcho(&"\nUnsealed {entries.len} file(s).")

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
  let meta = loadManifestMeta(repo, cfg = cfg)
  let entries = meta.entries
  if entries.len == 0:
    nvEcho("vault is empty")
    return

  banner("Sealing vault ...")

  # Verify all plaintext files exist first
  for e in entries:
    let src = resolvePath(cfg, e.path)
    if not fileExists(src):
      stderr.writeLine &"FATAL: plaintext missing: {src}"
      nvRaise("  Run 'nimvault unseal' first, or 'nimvault rm' to remove the entry.")

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
    let blob = findBlob(repo, cfg, e.id)
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
  var deks = loadDeks(repo, cfg)
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

  for e in todo:
    let inPath = resolvePath(cfg, e.path)
    let outPath = crypto.blobPath(repo, cfg, e.id)
    let key = newDek(cfg)
    encryptWithDek(cfg, key, inPath, outPath)
    deks[e.id] = key
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

  if todo.len > 0 or stale.len > 0:
    saveDeksGrouped(repo, cfg, deks, groupOf, recipsOf)

  # Flush new blobs before the manifest that vouches for them. The manifest
  # records each blob's hash, so a crash that persisted the manifest but not
  # the blob leaves an entry promising bytes that never landed, and the next
  # unseal reports tampering for a file nobody touched. Data first, then the
  # metadata pointing at it.
  for e in todo:
    let blob = findBlob(repo, cfg, e.id)
    if blob.len > 0 and fileExists(blob):
      syncPath(blob)
  if todo.len > 0:
    syncParentDir(crypto.blobPath(repo, cfg, todo[0].id))

  # Blob + plaintext content hashes; v4 manifest enables fast status without GPG
  var hashedEntries: seq[VaultEntry] = @[]
  for e in entries:
    if e.id in keptIds:
      hashedEntries.add(e)
    else:
      let blobPath = findBlob(repo, cfg, e.id)
      hashedEntries.add((e.id, e.path, sha256sum(blobPath), e.kind,
                         plainHashes.getOrDefault(e.id)))

  # The manifest is encrypted and signed, so writing it is itself a rewrite:
  # a seal that changed nothing would still leave one modified file behind and
  # a fresh signature over identical content. Leave it alone when it already
  # says exactly this.
  if todo.len == 0 and meta.sealKey == currentKey and hashedEntries == entries:
    nvEcho(&"\nNothing to seal; {entries.len} file(s) already current.")
    return

  saveManifest(repo, hashedEntries, cfg, currentKey)
  if keptIds.len > 0:
    nvEcho(&"\nSealed {todo.len} file(s), {keptIds.len} unchanged.")
  else:
    nvEcho(&"\nSealed {todo.len} file(s).")

proc add*(repo, path: string, cfg: GpgConfig, noGitignore = false) =
  ## Add a file by its target path.
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

  if not fileExists(absPath):
    nvRaise(&"FATAL: file not found: {absPath}")

  let storedPath = storePath(cfg, absPath, repo)

  # Check for duplicates
  var entries = loadManifest(repo, cfg = cfg)
  for e in entries:
    if resolvePath(cfg, e.path) == absPath:
      nvRaise(&"Already in vault: {storedPath}")

  # Check if file is already tracked by git (prevents plaintext leaks)
  let checkPath = if cfg.root.len > 0: storedPath else: absPath
  let (_, lsCode) = execCmdEx(&"git ls-files --error-unmatch {checkPath.quoteShell}",
    workingDir = repo)
  if lsCode == 0:
    stderr.writeLine &"FATAL: {storedPath} is already tracked by git"
    nvRaise(&"  Run 'git rm --cached {checkPath.quoteShell}' to untrack it first.")

  # Append to .gitignore if not already ignored (unless --no-gitignore)
  let (_, gitCheckCode) = execCmdEx(&"git check-ignore -q {checkPath.quoteShell}",
    workingDir = repo)
  if gitCheckCode != 0:
    if noGitignore:
      stderr.writeLine &"WARNING: {storedPath} is NOT gitignored"
    else:
      let gitignorePath = repo / ".gitignore"
      var f: File
      if open(f, gitignorePath, fmAppend):
        f.writeLine(storedPath)
        f.close()
        stderr.writeLine &"Added {storedPath} to .gitignore"
      else:
        stderr.writeLine &"WARNING: {storedPath} is NOT gitignored -- could not write .gitignore"

  let id = genId()
  let outPath = crypto.blobPath(repo, cfg, id)

  banner(&"Adding {storedPath} to vault ...")
  createDir(vaultDir(repo))
  encryptFile(cfg, absPath, outPath)
  let hash = sha256sum(outPath)
  let contentHash = sha256sum(absPath)
  entries.add((id, storedPath, hash, ekFile, contentHash))
  saveManifest(repo, entries, cfg)
  nvEcho(&"  id:   {id}")
  nvEcho(&"  path: {storedPath}")
  nvEcho(&"  blob: .vault/{id}{cfg.blobExt}")

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
      of pcFile, pcLinkToFile:
        filesToAdd.add(path)
      of pcDir, pcLinkToDir:
        walkDirRecursive(path)

  walkDirRecursive(absDirPath)

  if filesToAdd.len == 0:
    nvRaise(&"FATAL: directory is empty: {absDirPath}")

  banner(&"Adding directory {dirPath} ({filesToAdd.len} files) to vault ...")
  createDir(vaultDir(repo))

  var entries = loadManifest(repo, cfg = cfg)
  for filePath in filesToAdd:
    # Check for duplicates
    for e in entries:
      if resolvePath(cfg, e.path) == filePath:
        nvRaise(&"Already in vault: {filePath}")

    # Check if file is already tracked by git
    let storedPath = storePath(cfg, filePath, repo)
    let checkPath = if cfg.root.len > 0: storedPath else: filePath
    let (_, lsCode) = execCmdEx(&"git ls-files --error-unmatch {checkPath.quoteShell}",
      workingDir = repo)
    if lsCode == 0:
      stderr.writeLine &"FATAL: {storedPath} is already tracked by git"
      nvRaise(&"  Run 'git rm --cached {checkPath.quoteShell}' to untrack it first.")

    # Append to .gitignore if not already ignored
    let (_, gitCheckCode) = execCmdEx(&"git check-ignore -q {checkPath.quoteShell}",
      workingDir = repo)
    if gitCheckCode != 0:
      if noGitignore:
        stderr.writeLine &"WARNING: {storedPath} is NOT gitignored"
      else:
        let gitignorePath = repo / ".gitignore"
        var f: File
        if open(f, gitignorePath, fmAppend):
          f.writeLine(storedPath)
          f.close()
        else:
          stderr.writeLine &"WARNING: {storedPath} is NOT gitignored -- could not write .gitignore"

    # Encrypt and add to manifest
    let id = genId()
    let outPath = crypto.blobPath(repo, cfg, id)
    encryptFile(cfg, filePath, outPath)
    let hash = sha256sum(outPath)
    let contentHash = sha256sum(filePath)
    entries.add((id, storedPath, hash, ekFile, contentHash))
    nvEcho(&"  {storedPath}")

  saveManifest(repo, entries, cfg)
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

  var entries = loadManifest(repo, cfg = cfg)
  var found = false
  var newEntries: seq[VaultEntry] = @[]
  for e in entries:
    if resolvePath(cfg, e.path) == absPath:
      found = true
      let blobPath = findBlob(repo, cfg, e.id)
      if fileExists(blobPath):
        removeFile(blobPath)
        nvEcho(&"  Removed .vault/{e.id}{cfg.blobExt}")
      nvEcho(&"  Removed manifest entry: {e.path}")
    else:
      newEntries.add(e)

  if not found:
    nvRaise(&"Not in vault: {path}")

  saveManifest(repo, newEntries, cfg)
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
  let requireSig = not allowUnsigned
  let entries = loadManifest(repo, verifySig = requireSig, cfg = cfg)

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

    let inPath = findBlob(repo, cfg, e.id)
    if not fileExists(inPath):
      nvRaise(&"FATAL: vault blob missing: {inPath}")

    if e.hash.len > 0:
      let actualHash = sha256sum(inPath)
      if actualHash != e.hash:
        stderr.writeLine &"FATAL: integrity check failed for {e.path}"
        nvRaise("  The vault blob may have been tampered with.")
    elif requireSig:
      stderr.writeLine &"FATAL: missing blob hash for {e.path} (v1 manifest)"
      nvRaise("  Pass --allow-unsigned to accept unsigned vaults.")

    let deks = loadDeks(repo, cfg)
    if deks.hasKey(e.id):
      # v6: no in-band signature to verify, exactly as for age. Authenticity
      # came from the signed manifest and the blob digest checked just above.
      let tmp = getTempDir() / &"nimvault-get-{getCurrentProcessId()}-{e.id}"
      try:
        decryptWithDek(cfg, deks[e.id], inPath, tmp)
        result = readFile(tmp)
      finally:
        if fileExists(tmp): removeFile(tmp)
      return result
    return decryptToString(cfg, inPath, verifySig = requireSig)

  nvRaise(&"Not in vault: {path}")

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

  let newStored = storePath(cfg, newAbs, repo)

  var entries = loadManifest(repo, cfg = cfg)
  var found = false
  for e in entries.mitems:
    if resolvePath(cfg, e.path) == oldAbs:
      found = true
      if fileExists(oldAbs):
        createDir(newAbs.parentDir)
        moveFile(oldAbs, newAbs)
        nvEcho(&"  Moved {e.path} -> {newStored}")
      elif fileExists(newAbs):
        nvEcho(&"  File already at {newStored}")
      else:
        nvRaise(&"FATAL: file not found at {oldAbs} or {newAbs}")
      e.path = newStored
      break

  if not found:
    nvRaise(&"Not in vault: {oldPath}")

  saveManifest(repo, entries, cfg)
  nvEcho(&"  Updated manifest (blob unchanged)")

proc listReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly list (no terminal styling). Used by CLI and C ABI.
  let entries = loadManifest(repo, cfg = cfg)
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
  ".sqlite", ".sqlite3", ".db", ".gpg", ".age", ".key", ".pem", ".pfx",
]

const SkipDirs = [
  ".git", ".vault", ".cache", ".tmpclaude", ".pixi", ".venv", "venv",
  "target", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache",
  ".pytest_cache", ".tox", "build", "dist",
  # Claude Code / Codex runtime state: edit-history and session logs hold
  # historical versions of files, including keys that have since been
  # rotated or vaulted. Flagging them creates noise, not action.
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

type SecretHit = tuple[file, rule, snippet: string, line: int]

proc compileRules(): seq[(string, Regex)] =
  ## Returns (rule-name, compiled-regex) pairs. Order matters: more specific
  ## prefixes first so the Anthropic match wins against the generic sk- rule.
  @[
    ("anthropic-api-key", re(r"sk-ant-[A-Za-z0-9_\-]{24,}")),
    ("context7-api-key", re(r"ctx7sk-[a-f0-9\-]{20,}")),
    ("openai-api-key", re(r"sk-[A-Za-z0-9]{20,}")),
    ("github-pat", re(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("gitlab-pat", re(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("slack-token", re(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("aws-access-key", re(r"(AKIA|ASIA)[0-9A-Z]{16}")),
    ("ssh-private-key", re(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
  ]

proc isSkippedDir(dir: string): bool =
  let base = lastPathPart(dir)
  for s in SkipDirs:
    if base == s: return true
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

proc scanFile(path: string, rules: seq[(string, Regex)]): seq[SecretHit] =
  if not fileExists(path): return
  if getFileSize(path) > 2_000_000: return  # skip very large files
  var content: string
  try:
    content = readFile(path)
  except IOError:
    return
  var lineNo = 0
  for line in content.splitLines:
    inc lineNo
    # Short-circuit on extremely long lines (minified JS, base64 blobs)
    if line.len > 2000: continue
    for (name, rx) in rules:
      if line.contains(rx):
        let snip = if line.len > 120: line[0..117] & "..." else: line
        result.add((path, name, snip.strip(), lineNo))
        break  # one hit per line is enough

proc scan*(repo: string, target: string, cfg: GpgConfig) =
  ## Walk `target` (file or dir) and flag any file containing a secret
  ## pattern that is NOT already in the vault.
  let abs = if target.isAbsolute: target
            elif target.startsWith("~/"): expandHome(target)
            elif target.len == 0: repo
            else: absolutePath(target)

  if not fileExists(abs) and not dirExists(abs):
    nvRaise(&"FATAL: not a file or directory: {abs}")

  # Build set of vault-protected absolute paths (empty when not in a repo).
  var vaulted: HashSet[string]
  if repo.len > 0:
    for e in loadManifest(repo, cfg = cfg):
      vaulted.incl(resolvePath(cfg, e.path))

  let rules = compileRules()

  var files: seq[string]
  if fileExists(abs):
    files.add(abs)
  else:
    for path in walkDirRec(abs, yieldFilter = {pcFile},
                           skipSpecial = true, relative = false):
      # Check each path component against SkipDirs
      var skip = false
      for part in path.splitPath.head.split(DirSep):
        if part in SkipDirs:
          skip = true
          break
      if skip: continue
      files.add(path)

  var hits: seq[SecretHit]
  var scanned = 0
  for f in files:
    if f in vaulted: continue
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
      styledEcho fgRed, &"  [{h.rule}] {h.file}:{h.line}"
      echo &"    {h.snippet}"
    echo &"\nscanned {scanned} file(s); {hits.len} potential secret(s) in {hits.len} line(s)."
    echo "Fix: nimvault add <file> && nimvault seal, OR rotate+replace the literal."
  var report = &"Unvaulted secrets found ({hits.len})\n"
  for h in hits:
    report.add &"  [{h.rule}] {h.file}:{h.line}\n    {h.snippet}\n"
  report.add &"\nscanned {scanned} file(s); {hits.len} potential secret(s).\n"
  report.add "Fix: nimvault add <file> && nimvault seal, OR rotate+replace the literal."
  nvRaise(report)

proc statusReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly status (no colors). Fast path uses contentHash when present.
  let entries = loadManifest(repo, cfg = cfg)
  if entries.len == 0:
    return "vault is empty\n"

  result.add "Vault status\n"
  var needDecrypt: seq[VaultEntry] = @[]
  for e in entries:
    let localPath = resolvePath(cfg, e.path)
    let blobPath = findBlob(repo, cfg, e.id)

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
  type StRow = tuple[entry: VaultEntry, localHash, tmpPath, status: string, code: int]
  var rows: seq[StRow] = @[]
  for batchStart in countup(0, needDecrypt.high, batchSize):
    let batchEnd = min(batchStart + batchSize - 1, needDecrypt.high)
    var procs: seq[(VaultEntry, string, string, Process)] = @[]
    for i in batchStart .. batchEnd:
      let e = needDecrypt[i]
      let localPath = resolvePath(cfg, e.path)
      let localHash = sha256sum(localPath)
      let blobPath = findBlob(repo, cfg, e.id)
      let tmpPath = vaultDir(repo) / &".status-tmp-{e.id}"
      let p = decryptProcess(cfg, blobPath, tmpPath)
      procs.add((e, localHash, tmpPath, p))
    for (e, localHash, tmpPath, p) in procs:
      discard p.outputStream.readAll()
      let status = p.errorStream.readAll()
      let code = p.waitForExit()
      p.close()
      rows.add((e, localHash, tmpPath, status, code))

  for r in rows:
    defer:
      if fileExists(r.tmpPath): removeFile(r.tmpPath)
    if r.code != 0:
      result.add &"  [error]     {r.entry.path}\n"
      continue
    let vaultHash = sha256sum(r.tmpPath)
    if r.localHash == vaultHash:
      result.add &"  [in-sync]   {r.entry.path}\n"
    else:
      result.add &"  [modified]  {r.entry.path}\n"

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
  let meta = loadManifestMeta(repo, cfg = cfg)
  let entries = meta.entries
  if entries.len == 0:
    nvEcho("vault is empty")
    return

  if rekey:
    banner("Rekeying vault ...")
    seal(repo, cfg, force = true)
    nvEcho("Every payload re-encrypted under a fresh data key.")
    return

  banner("Rewrapping data keys ...")
  let lk {.used.} = acquire(repo)
  let deks = loadDeks(repo, cfg)
  if deks.len == 0:
    nvRaise("FATAL: no data keys to rewrap; this vault predates v6.\n" &
            "  Run 'nimvault seal --force' once to move it to v6.")
  # Recompute groups from the current rules, so rotate is also how a changed
  # `wrap` rule takes effect: an entry that moved group gets its key written to
  # the new group's file and dropped from the old one.
  var groupOf = initTable[string, string]()
  var recipsOf = initTable[string, seq[string]]()
  for e in entries:
    let recips = recipientsFor(cfg, e.path)
    let gid = groupId(recips)
    groupOf[e.id] = gid
    recipsOf[gid] = recips
  saveDeksGrouped(repo, cfg, deks, groupOf, recipsOf)

  var enveloped = 0
  for e in entries:
    if deks.hasKey(e.id):
      enveloped.inc
  nvEcho(&"\nRewrapped {deks.len} data key(s); {enveloped} of {entries.len} " &
         "entries are enveloped.")
  if enveloped < entries.len:
    nvEcho("Entries without a data key still carry the recipient inside the " &
           "blob;\n  'nimvault seal --force' migrates them.")

type CheckResult* = tuple[problems: seq[string], checked: int]

proc checkVault*(repo: string, cfg: GpgConfig): CheckResult =
  ## Verify the vault is internally consistent, without decrypting anything.
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
  ## checking each leaf against it is enough to detect a blob that has drifted,
  ## and needs no key material.
  let entries = loadManifest(repo, cfg = cfg)
  for e in entries:
    result.checked.inc
    let blob = findBlob(repo, cfg, e.id)
    if blob.len == 0 or not fileExists(blob):
      result.problems.add(&"no blob for {e.path}")
      continue
    if e.hash.len == 0:
      result.problems.add(&"no recorded hash for {e.path} (v1 manifest)")
      continue
    let actual = sha256sum(blob)
    if actual != e.hash:
      result.problems.add(&"blob does not match the manifest for {e.path}")

proc checkReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly check (no colors, no exit).
  let r = checkVault(repo, cfg)
  if r.checked == 0:
    return "vault is empty\n"
  for p in r.problems:
    result.add &"  {p}\n"
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
  if r.problems.len > 0:
    nvRaise(&"{r.problems.len} of {r.checked} entries are inconsistent " &
            "(seal, or restore the missing blob)")
  nvEcho(&"\n{r.checked} entries consistent with the manifest.")

proc status*(repo: string, cfg: GpgConfig) =
  ## Terminal status (colors). Delegates logic to statusReport for library reuse.
  let entries = loadManifest(repo, cfg = cfg)
  if entries.len == 0:
    echo "vault is empty"
    return

  banner("Vault status")
  var needDecrypt: seq[VaultEntry] = @[]
  for e in entries:
    let localPath = resolvePath(cfg, e.path)
    let blobPath = findBlob(repo, cfg, e.id)

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
  type StRow = tuple[entry: VaultEntry, localHash, tmpPath, status: string, code: int]
  var rows: seq[StRow] = @[]
  for batchStart in countup(0, needDecrypt.high, batchSize):
    let batchEnd = min(batchStart + batchSize - 1, needDecrypt.high)
    var procs: seq[(VaultEntry, string, string, Process)] = @[]
    for i in batchStart .. batchEnd:
      let e = needDecrypt[i]
      let localPath = resolvePath(cfg, e.path)
      let localHash = sha256sum(localPath)
      let blobPath = findBlob(repo, cfg, e.id)
      let tmpPath = vaultDir(repo) / &".status-tmp-{e.id}"
      let p = decryptProcess(cfg, blobPath, tmpPath)
      procs.add((e, localHash, tmpPath, p))
    for (e, localHash, tmpPath, p) in procs:
      discard p.outputStream.readAll()
      let status = p.errorStream.readAll()
      let code = p.waitForExit()
      p.close()
      rows.add((e, localHash, tmpPath, status, code))

  for r in rows:
    defer:
      if fileExists(r.tmpPath): removeFile(r.tmpPath)
    if r.code != 0:
      styledEcho fgRed, &"  [error]     {r.entry.path}"
      continue
    let vaultHash = sha256sum(r.tmpPath)
    if r.localHash == vaultHash:
      styledEcho fgGreen, &"  [in-sync]   {r.entry.path}"
    else:
      styledEcho fgRed, &"  [modified]  {r.entry.path}"


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
