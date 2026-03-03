## Vault commands: seal, unseal, add, rm, mv, list, status.
##
## All commands take a repo path and GpgConfig.
## Parallel GPG via startProcess with direct invocation (no shell).

import std/[os, osproc, strutils, strformat, streams, terminal]
import ./gpg, ./manifest

proc banner(msg: string) =
  let w = terminalWidth()
  let line = repeat('-', min(w, 72))
  echo ""
  echo line
  styledEcho fgCyan, styleBright, "  ", msg
  echo line

proc unseal*(repo: string, cfg: GpgConfig) =
  let entries = loadManifest(repo, verifySig = true)
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
    # Blob hash verification (v2 manifests only)
    if e.hash.len > 0:
      let actualHash = sha256sum(inPath)
      if actualHash != e.hash:
        stderr.writeLine &"FATAL: integrity check failed for {e.path}"
        stderr.writeLine &"  Expected: {e.hash}"
        stderr.writeLine &"  Actual:   {actualHash}"
        stderr.writeLine "  The vault blob may have been tampered with."
        quit 1

  # Launch all GPG decrypts in parallel (direct invocation, no shell)
  var procs: seq[(VaultEntry, Process)] = @[]
  for e in entries:
    let inPath = vaultDir(repo) / &"{e.id}.gpg"
    let outPath = resolvePath(cfg, e.path)
    createDir(outPath.parentDir)
    let p = startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
               "-d", "-o", outPath, inPath],
      options = {poUsePath})
    procs.add((e, p))

  # Collect results and check signatures
  for (e, p) in procs:
    discard p.outputStream.readAll()  # empty with -o
    let status = p.errorStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      stderr.writeLine &"FATAL: failed to unseal {e.path}\n{status}"
      quit 1
    if "BADSIG" in status or "ERRSIG" in status:
      stderr.writeLine &"FATAL: bad signature on blob for {e.path}"
      stderr.writeLine "  The vault may have been tampered with."
      quit 1
    if "GOODSIG" notin status:
      stderr.writeLine &"WARNING: unsigned blob for {e.path}"
      stderr.writeLine "  Run 'nimvault seal' to re-encrypt with signatures."
    setFilePermissions(resolvePath(cfg, e.path), {fpUserRead, fpUserWrite})
    echo &"  {e.path}"

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

  # Launch all GPG encrypts in parallel (direct invocation, no shell)
  var procs: seq[(VaultEntry, Process)] = @[]
  for e in entries:
    let inPath = resolvePath(cfg, e.path)
    let outPath = vaultDir(repo) / &"{e.id}.gpg"
    let p = startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--trust-model", "always",
               "--sign", "-e", "-r", cfg.recipient,
               "--set-filename", "", "-o", outPath, inPath],
      options = {poUsePath, poStdErrToStdOut})
    procs.add((e, p))

  # Collect results
  for (e, p) in procs:
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      stderr.writeLine &"FATAL: failed to seal {e.path}\n{output}"
      quit 1
    echo &"  {e.path}"

  # Compute blob hashes and save v2 manifest
  var hashedEntries: seq[VaultEntry] = @[]
  for e in entries:
    let blobPath = vaultDir(repo) / &"{e.id}.gpg"
    hashedEntries.add((e.id, e.path, sha256sum(blobPath)))

  # Re-encrypt manifest (signed, v2 with hashes)
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
  entries.add((id, storedPath, hash))
  saveManifest(repo, entries, cfg)
  echo &"  id:   {id}"
  echo &"  path: {storedPath}"
  echo &"  blob: .vault/{id}.gpg"

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

proc list*(repo: string, cfg: GpgConfig) =
  let entries = loadManifest(repo)
  if entries.len == 0:
    echo "vault is empty"
    return
  for e in entries:
    echo &"  {e.id}  {e.path}"

proc status*(repo: string, cfg: GpgConfig) =
  let entries = loadManifest(repo)
  if entries.len == 0:
    echo "vault is empty"
    return

  banner("Vault status")
  for e in entries:
    let localPath = resolvePath(cfg, e.path)
    let blobPath = vaultDir(repo) / &"{e.id}.gpg"

    if not fileExists(localPath):
      styledEcho fgYellow, &"  [missing]   {e.path}"
      continue

    if not fileExists(blobPath):
      styledEcho fgRed, &"  [no-blob]   {e.path}"
      continue

    # Compare SHA-256 of local file vs decrypted vault blob
    let localHash = sha256sum(localPath)
    let tmpPath = vaultDir(repo) / &".status-tmp-{e.id}"
    gpgDecrypt(blobPath, tmpPath)
    let vaultHash = sha256sum(tmpPath)
    removeFile(tmpPath)

    if localHash == vaultHash:
      styledEcho fgGreen, &"  [in-sync]   {e.path}"
    else:
      styledEcho fgRed, &"  [modified]  {e.path}"
