## Vault commands: seal, unseal, add, rm, mv, list, status.
##
## All commands take a repo path and GpgConfig.
## Parallel GPG via startProcess is preserved from the original implementation.

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
  let entries = loadManifest(repo)
  if entries.len == 0:
    echo "vault is empty"
    return

  banner("Unsealing vault ...")

  # Launch all GPG decrypts in parallel
  var procs: seq[(VaultEntry, Process)] = @[]
  for e in entries:
    let inPath = vaultDir(repo) / &"{e.id}.gpg"
    let outPath = resolvePath(cfg, e.path)
    if not fileExists(inPath):
      stderr.writeLine &"FATAL: vault blob missing: {inPath}"
      quit 1
    createDir(outPath.parentDir)
    let p = startProcess("/bin/bash",
      args = ["-c", &"gpg --batch --yes --quiet -d -o {outPath.quoteShell} {inPath.quoteShell}"],
      options = {poUsePath, poStdErrToStdOut})
    procs.add((e, p))

  # Collect results
  for (e, p) in procs:
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      stderr.writeLine &"FATAL: failed to unseal {e.path}\n{output}"
      quit 1
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

  # Launch all GPG encrypts in parallel
  var procs: seq[(VaultEntry, Process)] = @[]
  for e in entries:
    let inPath = resolvePath(cfg, e.path)
    let outPath = vaultDir(repo) / &"{e.id}.gpg"
    let p = startProcess("/bin/bash",
      args = ["-c", &"gpg --batch --yes --quiet --trust-model always " &
        &"-e -r {cfg.recipient} --set-filename \"\" -o {outPath.quoteShell} {inPath.quoteShell}"],
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

  # Re-encrypt manifest
  saveManifest(repo, entries, cfg)
  echo &"\nSealed {entries.len} file(s)."

proc add*(repo, path: string, cfg: GpgConfig) =
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

  # Warn if not gitignored
  let checkPath = if cfg.root.len > 0: storedPath else: absPath
  let (_, gitCheckCode) = execCmdEx(&"git check-ignore -q {checkPath.quoteShell}",
    workingDir = repo)
  if gitCheckCode != 0:
    stderr.writeLine &"WARNING: {storedPath} is NOT gitignored -- add it to .gitignore"

  let id = genId()
  let outPath = vaultDir(repo) / &"{id}.gpg"

  banner(&"Adding {storedPath} to vault ...")
  createDir(vaultDir(repo))
  gpgEncrypt(cfg, absPath, outPath)
  entries.add((id, storedPath))
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
