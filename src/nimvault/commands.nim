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
    let outPath = expandHome(e.path)
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
    setFilePermissions(expandHome(e.path), {fpUserRead, fpUserWrite})
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
    let src = expandHome(e.path)
    if not fileExists(src):
      stderr.writeLine &"FATAL: plaintext missing: {src}"
      stderr.writeLine "  Run 'nimvault unseal' first, or 'nimvault rm' to remove the entry."
      quit 1

  # Launch all GPG encrypts in parallel
  var procs: seq[(VaultEntry, Process)] = @[]
  for e in entries:
    let inPath = expandHome(e.path)
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
  ## Add a file by its absolute target path (where it lives on disk).
  let absPath = expandHome(path)

  if not fileExists(absPath):
    stderr.writeLine &"FATAL: file not found: {absPath}"
    quit 1

  # Store the path with ~ for portability across machines
  let homePath = if absPath.startsWith(getHomeDir()):
    "~/" & relativePath(absPath, getHomeDir())
  else:
    absPath

  # Check for duplicates
  var entries = loadManifest(repo)
  for e in entries:
    if expandHome(e.path) == absPath:
      stderr.writeLine &"Already in vault: {homePath}"
      quit 1

  let id = genId()
  let outPath = vaultDir(repo) / &"{id}.gpg"

  banner(&"Adding {homePath} to vault ...")
  createDir(vaultDir(repo))
  gpgEncrypt(cfg, absPath, outPath)
  entries.add((id, homePath))
  saveManifest(repo, entries, cfg)
  echo &"  id:   {id}"
  echo &"  path: {homePath}"
  echo &"  blob: .vault/{id}.gpg"

proc remove*(repo, path: string, cfg: GpgConfig) =
  let absPath = expandHome(path)

  var entries = loadManifest(repo)
  var found = false
  var newEntries: seq[VaultEntry] = @[]
  for e in entries:
    if expandHome(e.path) == absPath:
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
  let oldAbs = expandHome(oldPath)
  let newAbs = expandHome(newPath)

  let newHome = if newAbs.startsWith(getHomeDir()):
    "~/" & relativePath(newAbs, getHomeDir())
  else:
    newAbs

  var entries = loadManifest(repo)
  var found = false
  for e in entries.mitems:
    if expandHome(e.path) == oldAbs:
      found = true
      if fileExists(oldAbs):
        createDir(newAbs.parentDir)
        moveFile(oldAbs, newAbs)
        echo &"  Moved {e.path} -> {newHome}"
      elif fileExists(newAbs):
        echo &"  File already at {newHome}"
      else:
        stderr.writeLine &"FATAL: file not found at {oldAbs} or {newAbs}"
        quit 1
      e.path = newHome
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
    let localPath = expandHome(e.path)
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
