## Vault commands: seal, unseal, add, rm, mv, list, status, scan.
##
## All commands take a repo path and GpgConfig.
## Parallel GPG via startProcess with direct invocation (no shell).

import std/[os, osproc, strutils, strformat, streams, terminal, re, sets]
import ./gpg, ./manifest

proc banner(msg: string) =
  let w = terminalWidth()
  let line = repeat('-', min(w, 72))
  echo ""
  echo line
  styledEcho fgCyan, styleBright, "  ", msg
  echo line

proc unseal*(repo: string, cfg: GpgConfig, allowUnsigned = false) =
  let requireSig = not allowUnsigned
  let entries = loadManifest(repo, verifySig = requireSig)
  if entries.len == 0:
    echo "vault is empty"
    return

  banner("Unsealing vault ...")

  # Verify blob integrity and path safety before any decryption
  for e in entries:
    let inPath = vaultDir(repo) / &"{e.id}.gpg"
    if not fileExists(inPath):
      stderr.writeLine &"FATAL: vault blob missing: {inPath}"
      quit 1
    # Path traversal check
    if not isPathSafe(cfg, e.path):
      stderr.writeLine &"FATAL: unsafe path in manifest: {e.path}"
      stderr.writeLine &"  Resolved: {normalizedPath(resolvePath(cfg, e.path))}"
      stderr.writeLine "  Possible directory traversal attack."
      quit 1
    # Blob hash verification
    if e.hash.len > 0:
      let actualHash = sha256sum(inPath)
      if actualHash != e.hash:
        stderr.writeLine &"FATAL: integrity check failed for {e.path}"
        stderr.writeLine &"  Expected: {e.hash}"
        stderr.writeLine &"  Actual:   {actualHash}"
        stderr.writeLine "  The vault blob may have been tampered with."
        quit 1
    elif requireSig:
      stderr.writeLine &"FATAL: missing blob hash for {e.path} (v1 manifest)"
      stderr.writeLine "  Pass --allow-unsigned to accept unsigned vaults."
      quit 1

  # Decrypt to temp files first (never directly to final path).
  # This prevents release of unverified plaintext: GPG streams content to
  # disk before the signature check completes, so writing to the final
  # path would expose unverified data even if we abort on BADSIG.
  # Process in batches to avoid GPG memory exhaustion (NIMVAULT_GPG_PARALLEL).
  let batchSize = gpgParallelism()
  var tmpPaths: seq[string] = @[]
  type DecryptResult = tuple[entry: VaultEntry, tmpPath, status: string, code: int]
  var results: seq[DecryptResult] = @[]
  for batchStart in countup(0, entries.high, batchSize):
    let batchEnd = min(batchStart + batchSize - 1, entries.high)
    var procs: seq[(VaultEntry, string, Process)] = @[]
    for i in batchStart .. batchEnd:
      let e = entries[i]
      let inPath = vaultDir(repo) / &"{e.id}.gpg"
      let outPath = resolvePath(cfg, e.path)
      let tmpPath = outPath & ".nimvault-tmp"
      tmpPaths.add(tmpPath)
      createDir(outPath.parentDir)
      let p = startProcess("gpg",
        args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
                 "-d", "-o", tmpPath, inPath],
        options = {poUsePath})
      procs.add((e, tmpPath, p))

    # Collect results for this batch
    for (e, tmpPath, p) in procs:
      discard p.outputStream.readAll()  # empty with -o
      let status = p.errorStream.readAll()
      let code = p.waitForExit()
      p.close()
      results.add((e, tmpPath, status, code))

  # Abort helper: remove all temp files before exiting
  template abortUnseal(msgs: varargs[string]) =
    for tp in tmpPaths:
      if fileExists(tp): removeFile(tp)
    for msg in msgs:
      stderr.writeLine msg
    quit 1

  # Verify all decryption results and signatures
  for r in results:
    if r.code != 0:
      abortUnseal(&"FATAL: failed to unseal {r.entry.path}", r.status)
    # Bad signatures are always fatal (even with --allow-unsigned)
    if "BADSIG" in r.status or "ERRSIG" in r.status:
      abortUnseal(&"FATAL: bad signature on blob for {r.entry.path}",
        "  The vault may have been tampered with.")
    # Missing signatures: fatal unless --allow-unsigned
    if requireSig and "GOODSIG" notin r.status:
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
    echo &"  {r.entry.path}"

  echo &"\nUnsealed {entries.len} file(s)."

proc seal*(repo: string, cfg: GpgConfig) =
  let entries = loadManifest(repo)
  if entries.len == 0:
    echo "vault is empty"
    return

  banner("Sealing vault ...")

  # Verify all plaintext files exist first
  for e in entries:
    let src = resolvePath(cfg, e.path)
    if not fileExists(src):
      stderr.writeLine &"FATAL: plaintext missing: {src}"
      stderr.writeLine "  Run 'nimvault unseal' first, or 'nimvault rm' to remove the entry."
      quit 1

  # Launch GPG encrypts in batches (NIMVAULT_GPG_PARALLEL, default 8).
  # GPG sign+encrypt is memory-intensive; launching all at once can trigger
  # "Cannot allocate memory" on systems with many vault entries.
  let batchSize = gpgParallelism()
  for batchStart in countup(0, entries.high, batchSize):
    let batchEnd = min(batchStart + batchSize - 1, entries.high)
    var procs: seq[(VaultEntry, Process)] = @[]
    for i in batchStart .. batchEnd:
      let e = entries[i]
      let inPath = resolvePath(cfg, e.path)
      let outPath = vaultDir(repo) / &"{e.id}.gpg"
      let p = startProcess("gpg",
        args = @["--batch", "--yes", "--quiet", "--trust-model", "always",
                 "--sign", "-e", "-r", cfg.recipient,
                 "--set-filename", "", "-o", outPath, inPath],
        options = {poUsePath, poStdErrToStdOut})
      procs.add((e, p))

    # Collect results for this batch
    for (e, p) in procs:
      let output = p.outputStream.readAll()
      let code = p.waitForExit()
      p.close()
      if code != 0:
        stderr.writeLine &"FATAL: failed to seal {e.path}\n{output}"
        quit 1
      echo &"  {e.path}"

  # Blob + plaintext content hashes; v4 manifest enables fast status without GPG
  var hashedEntries: seq[VaultEntry] = @[]
  for e in entries:
    let blobPath = vaultDir(repo) / &"{e.id}.gpg"
    let plainPath = resolvePath(cfg, e.path)
    hashedEntries.add((e.id, e.path, sha256sum(blobPath), e.kind, sha256sum(plainPath)))

  saveManifest(repo, hashedEntries, cfg)
  echo &"\nSealed {entries.len} file(s)."

proc add*(repo, path: string, cfg: GpgConfig, noGitignore = false) =
  ## Add a file by its target path.
  let absPath = if path.isAbsolute:
    path
  elif path.startsWith("~/"):
    expandHome(path)
  elif cfg.root.len > 0:
    cfg.root / path
  else:
    expandHome(path)

  if not fileExists(absPath):
    stderr.writeLine &"FATAL: file not found: {absPath}"
    quit 1

  let storedPath = storePath(cfg, absPath, repo)

  # Check for duplicates
  var entries = loadManifest(repo)
  for e in entries:
    if resolvePath(cfg, e.path) == absPath:
      stderr.writeLine &"Already in vault: {storedPath}"
      quit 1

  # Check if file is already tracked by git (prevents plaintext leaks)
  let checkPath = if cfg.root.len > 0: storedPath else: absPath
  let (_, lsCode) = execCmdEx(&"git ls-files --error-unmatch {checkPath.quoteShell}",
    workingDir = repo)
  if lsCode == 0:
    stderr.writeLine &"FATAL: {storedPath} is already tracked by git"
    stderr.writeLine &"  Run 'git rm --cached {checkPath.quoteShell}' to untrack it first."
    quit 1

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
  let outPath = vaultDir(repo) / &"{id}.gpg"

  banner(&"Adding {storedPath} to vault ...")
  createDir(vaultDir(repo))
  gpgEncrypt(cfg, absPath, outPath)
  let hash = sha256sum(outPath)
  let contentHash = sha256sum(absPath)
  entries.add((id, storedPath, hash, ekFile, contentHash))
  saveManifest(repo, entries, cfg)
  echo &"  id:   {id}"
  echo &"  path: {storedPath}"
  echo &"  blob: .vault/{id}.gpg"

proc addDir*(repo, dirPath: string, cfg: GpgConfig, noGitignore = false) =
  ## Add a directory recursively to the vault.
  let absDirPath = if dirPath.isAbsolute:
    dirPath
  elif dirPath.startsWith("~/"):
    expandHome(dirPath)
  elif cfg.root.len > 0:
    cfg.root / dirPath
  else:
    expandHome(dirPath)

  if not dirExists(absDirPath):
    stderr.writeLine &"FATAL: directory not found: {absDirPath}"
    quit 1

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
    stderr.writeLine &"FATAL: directory is empty: {absDirPath}"
    quit 1

  banner(&"Adding directory {dirPath} ({filesToAdd.len} files) to vault ...")
  createDir(vaultDir(repo))

  var entries = loadManifest(repo)
  for filePath in filesToAdd:
    # Check for duplicates
    for e in entries:
      if resolvePath(cfg, e.path) == filePath:
        stderr.writeLine &"Already in vault: {filePath}"
        quit 1

    # Check if file is already tracked by git
    let storedPath = storePath(cfg, filePath, repo)
    let checkPath = if cfg.root.len > 0: storedPath else: filePath
    let (_, lsCode) = execCmdEx(&"git ls-files --error-unmatch {checkPath.quoteShell}",
      workingDir = repo)
    if lsCode == 0:
      stderr.writeLine &"FATAL: {storedPath} is already tracked by git"
      stderr.writeLine &"  Run 'git rm --cached {checkPath.quoteShell}' to untrack it first."
      quit 1

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
    let outPath = vaultDir(repo) / &"{id}.gpg"
    gpgEncrypt(cfg, filePath, outPath)
    let hash = sha256sum(outPath)
    let contentHash = sha256sum(filePath)
    entries.add((id, storedPath, hash, ekFile, contentHash))
    echo &"  {storedPath}"

  saveManifest(repo, entries, cfg)
  echo &"\nAdded {filesToAdd.len} file(s) from directory."

proc remove*(repo, path: string, cfg: GpgConfig) =
  let absPath = if path.isAbsolute:
    path
  elif path.startsWith("~/"):
    expandHome(path)
  elif cfg.root.len > 0:
    cfg.root / path
  else:
    expandHome(path)

  var entries = loadManifest(repo)
  var found = false
  var newEntries: seq[VaultEntry] = @[]
  for e in entries:
    if resolvePath(cfg, e.path) == absPath:
      found = true
      let blobPath = vaultDir(repo) / &"{e.id}.gpg"
      if fileExists(blobPath):
        removeFile(blobPath)
        echo &"  Removed .vault/{e.id}.gpg"
      echo &"  Removed manifest entry: {e.path}"
    else:
      newEntries.add(e)

  if not found:
    stderr.writeLine &"Not in vault: {path}"
    quit 1

  saveManifest(repo, newEntries, cfg)
  echo "  (local plaintext file NOT deleted)"

proc move*(repo, oldPath, newPath: string, cfg: GpgConfig) =
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

  var entries = loadManifest(repo)
  var found = false
  for e in entries.mitems:
    if resolvePath(cfg, e.path) == oldAbs:
      found = true
      if fileExists(oldAbs):
        createDir(newAbs.parentDir)
        moveFile(oldAbs, newAbs)
        echo &"  Moved {e.path} -> {newStored}"
      elif fileExists(newAbs):
        echo &"  File already at {newStored}"
      else:
        stderr.writeLine &"FATAL: file not found at {oldAbs} or {newAbs}"
        quit 1
      e.path = newStored
      break

  if not found:
    stderr.writeLine &"Not in vault: {oldPath}"
    quit 1

  saveManifest(repo, entries, cfg)
  echo &"  Updated manifest (blob unchanged)"

proc listReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly list (no terminal styling). Used by CLI and C ABI.
  let entries = loadManifest(repo)
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
    stderr.writeLine &"FATAL: not a file or directory: {abs}"
    quit 1

  # Build set of vault-protected absolute paths (empty when not in a repo).
  var vaulted: HashSet[string]
  if repo.len > 0:
    for e in loadManifest(repo):
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
    echo &"scanned {scanned} file(s); no unvaulted secrets found"
    return

  banner(&"Unvaulted secrets found ({hits.len})")
  for h in hits:
    styledEcho fgRed, &"  [{h.rule}] {h.file}:{h.line}"
    echo &"    {h.snippet}"
  echo &"\nscanned {scanned} file(s); {hits.len} potential secret(s) in {hits.len} line(s)."
  echo "Fix: nimvault add <file> && nimvault seal, OR rotate+replace the literal."
  quit 1

proc statusReport*(repo: string, cfg: GpgConfig): string =
  ## Library-friendly status (no colors). Fast path uses contentHash when present.
  let entries = loadManifest(repo)
  if entries.len == 0:
    return "vault is empty\n"

  result.add "Vault status\n"
  var needDecrypt: seq[VaultEntry] = @[]
  for e in entries:
    let localPath = resolvePath(cfg, e.path)
    let blobPath = vaultDir(repo) / &"{e.id}.gpg"

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
      let blobPath = vaultDir(repo) / &"{e.id}.gpg"
      let tmpPath = vaultDir(repo) / &".status-tmp-{e.id}"
      let p = startProcess("gpg",
        args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
                 "-d", "-o", tmpPath, blobPath],
        options = {poUsePath})
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

proc status*(repo: string, cfg: GpgConfig) =
  ## Terminal status (colors). Delegates logic to statusReport for library reuse.
  let entries = loadManifest(repo)
  if entries.len == 0:
    echo "vault is empty"
    return

  banner("Vault status")
  var needDecrypt: seq[VaultEntry] = @[]
  for e in entries:
    let localPath = resolvePath(cfg, e.path)
    let blobPath = vaultDir(repo) / &"{e.id}.gpg"

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
      let blobPath = vaultDir(repo) / &"{e.id}.gpg"
      let tmpPath = vaultDir(repo) / &".status-tmp-{e.id}"
      let p = startProcess("gpg",
        args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
                 "-d", "-o", tmpPath, blobPath],
        options = {poUsePath})
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
