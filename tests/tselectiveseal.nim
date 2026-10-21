## Exact-file seal tests use only temporary stores and throwaway keys.

import std/[os, osproc, strutils, strformat, tables, tempfiles, unittest]
import nimvault/[gpg, manifest, commands, crypto, dek]

const SourceRoot = currentSourcePath().parentDir.parentDir

type Fixture = object
  repo: string
  cfg: GpgConfig
  paths: seq[string]

proc vaultBytes(repo: string): Table[string, string] =
  for path in walkDirRec(vaultDir(repo)):
    doAssert not symlinkExists(path)
    result[relativePath(path, vaultDir(repo))] = readFile(path)

proc reject(action: proc(), reason: string) =
  var raised = false
  try:
    action()
  except NimvaultError as err:
    raised = true
    doAssert reason in err.msg, err.msg
  doAssert raised, "expected rejection: " & reason

proc entryFor(f: Fixture, index: int): VaultEntry =
  for entry in loadManifest(f.repo, verifySig = true, cfg = f.cfg):
    if resolvePath(f.cfg, entry.path) == f.paths[index]:
      return entry
  raise newException(ValueError, "fixture entry not found")

proc fixture(keyId, fingerprint: string, combined = false): Fixture =
  result.repo = createTempDir("nimvault_selected_", "_store")
  result.cfg = GpgConfig(recipient: keyId, root: result.repo / "plain")
  # Different spellings of the same throwaway key form distinct wrap groups.
  result.cfg.wraps = @["other.txt:" & fingerprint]
  createDir(result.cfg.root)
  ensureVaultDir(result.repo)
  writeFile(vaultDir(result.repo) / "config",
    &"recipient = {keyId}\nroot = {result.cfg.root}\n" &
    &"wrap = other.txt:{fingerprint}\n")
  var entries: seq[VaultEntry] = @[]
  var deks: DekTable
  var groupOf = initTable[string, string]()
  var recipsOf = initTable[string, seq[string]]()
  for name in ["first file.txt", "second.txt", "other.txt"]:
    let path = result.cfg.root / name
    result.paths.add(path)
    writeFile(path, "original:" & name)
    let id = genId()
    let blob = crypto.blobPath(result.repo, result.cfg, id)
    if combined:
      encryptFile(result.cfg, path, blob)
    else:
      let key = newDek(result.cfg)
      encryptWithDek(result.cfg, key, path, blob)
      deks[id] = key
    let stored = storePath(result.cfg, path, result.repo)
    entries.add((id, stored, sha256sum(blob), ekFile, sha256sum(path)))
    let recipients = recipientsFor(result.cfg, stored)
    let group = groupId(recipients)
    groupOf[id] = group
    recipsOf[group] = recipients
  if not combined:
    saveDeksGrouped(result.repo, result.cfg, deks, groupOf, recipsOf)
  saveManifest(result.repo, entries, result.cfg, sealKey(result.cfg),
               envelope = not combined)

proc main() =
  let home = createTempDir("nimvault_selected_", "_gpg")
  setFilePermissions(home, {fpUserRead, fpUserWrite, fpUserExec})
  let previousHome = getEnv("GNUPGHOME")
  putEnv("GNUPGHOME", home)
  defer:
    if previousHome.len > 0: putEnv("GNUPGHOME", previousHome)
    else: delEnv("GNUPGHOME")
    removeDir(home)
  let keyScript = home / "keygen.txt"
  writeFile(keyScript, """
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Selective Seal Fixture
Name-Email: selective@nimvault.test
Expire-Date: 0
%commit
""")
  let (keyOutput, keyCode) = execCmdEx(
    "gpg --batch --gen-key " & keyScript.quoteShell)
  doAssert keyCode == 0, keyOutput
  let (keys, listCode) = execCmdEx("gpg --batch --with-colons --list-keys")
  doAssert listCode == 0, keys
  var keyId, fingerprint: string
  for line in keys.splitLines:
    let fields = line.split(':')
    if fields.len > 9 and fields[0] == "pub" and keyId.len == 0:
      keyId = fields[4]
    elif fields.len > 9 and fields[0] == "fpr" and fingerprint.len == 0:
      fingerprint = fields[9]
  doAssert keyId.len > 0 and fingerprint.len > 0

  suite "selected seal":
    test "changed and absent unselected plaintext remains unsealed":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      let second = entryFor(f, 1)
      let other = entryFor(f, 2)
      let before = vaultBytes(f.repo)
      writeFile(f.paths[0], "selected value\n")
      writeFile(f.paths[1], "unselected edit")
      removeFile(f.paths[2])
      seal(f.repo, f.cfg, only = @[f.paths[0]])
      let after = vaultBytes(f.repo)
      doAssert entryFor(f, 1) == second
      doAssert entryFor(f, 2) == other
      for entry in [second, other]:
        let blob = relativePath(findBlob(f.repo, f.cfg, entry.id), vaultDir(f.repo))
        let record = relativePath(findEntryFile(f.repo, f.cfg, entry.id), vaultDir(f.repo))
        doAssert after[blob] == before[blob]
        doAssert after[record] == before[record]
      let otherGroup = groupId(recipientsFor(f.cfg, other.path))
      let otherKeys = relativePath(groupKeysPath(f.repo, f.cfg, otherGroup),
                                   vaultDir(f.repo))
      doAssert after[otherKeys] == before[otherKeys]
      let stub = relativePath(manifestPath(f.repo, f.cfg), vaultDir(f.repo))
      doAssert after[stub] == before[stub]
      doAssert get(f.repo, f.paths[0], f.cfg) == "selected value\n"
      doAssert get(f.repo, f.paths[1], f.cfg) == "original:second.txt"
      doAssert get(f.repo, f.paths[2], f.cfg) == "original:other.txt"
      doAssert readFile(f.paths[1]) == "unselected edit"
      doAssert not fileExists(f.paths[2])

    test "a current selected entry leaves sealed bytes unchanged":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      writeFile(f.paths[1], "dirty but unselected")
      let before = vaultBytes(f.repo)
      seal(f.repo, f.cfg, only = @[f.paths[0]])
      let after = vaultBytes(f.repo)
      for path, bytes in before:
        doAssert after[path] == bytes, path
      # A no-op seal still backfills the plaintext blob-index. It must not
      # rewrite records, blobs, keys, or the manifest, and a second run
      # must not churn the index either.
      doAssert "blob-index" notin before
      doAssert after.len == before.len + 1
      let index = after["blob-index"]
      for i in 0 .. 2:
        let entry = entryFor(f, i)
        doAssert (entry.id & " " & entry.hash) in index
      seal(f.repo, f.cfg, only = @[f.paths[0]])
      doAssert vaultBytes(f.repo) == after

    test "selected key-group updates retain keys outside the entry view":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      let first = entryFor(f, 0)
      let group = groupId(recipientsFor(f.cfg, first.path))
      let path = groupKeysPath(f.repo, f.cfg, group)
      let work = privateWorkDir()
      defer: removeDir(work)
      let plain = work / "keys.plain"
      let hiddenId = genId()
      let hiddenKey = newDek(f.cfg)
      writeFile(plain, decryptToString(f.cfg, path, false) &
        &"{hiddenId}\t{hiddenKey}\n")
      encryptFileTo(f.cfg, recipientsFor(f.cfg, first.path), plain, path,
                     sign = false)
      writeFile(f.paths[0], "selected change")
      seal(f.repo, f.cfg, only = @[f.paths[0]])
      doAssert loadDeks(f.repo, f.cfg)[hiddenId] == hiddenKey
      doAssert get(f.repo, f.paths[0], f.cfg) == "selected change"

    test "force and repeated normalized selectors affect one entry":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      let first = entryFor(f, 0)
      let second = entryFor(f, 1)
      let before = vaultBytes(f.repo)
      let firstBlob = relativePath(findBlob(f.repo, f.cfg, first.id), vaultDir(f.repo))
      let secondBlob = relativePath(findBlob(f.repo, f.cfg, second.id), vaultDir(f.repo))
      seal(f.repo, f.cfg, force = true,
           only = @["first file.txt", f.cfg.root / "." / "first file.txt"])
      let after = vaultBytes(f.repo)
      doAssert after[firstBlob] != before[firstBlob]
      doAssert after[secondBlob] == before[secondBlob]
      doAssert entryFor(f, 1) == second

    test "all selectors and selected plaintext are checked before writes":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      writeFile(f.paths[0], "selected edit")
      let before = vaultBytes(f.repo)
      reject(proc() = seal(f.repo, f.cfg,
        only = @[f.paths[0], f.cfg.root / "absent"]), "Not in vault")
      doAssert vaultBytes(f.repo) == before
      removeFile(f.paths[1])
      reject(proc() = seal(f.repo, f.cfg,
        only = @[f.paths[0], f.paths[1]]), "Run 'nimvault unseal' first")
      doAssert vaultBytes(f.repo) == before

    test "directory and empty selectors do not expand":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      let before = vaultBytes(f.repo)
      reject(proc() = seal(f.repo, f.cfg, only = @[f.cfg.root]), "Not in vault")
      reject(proc() = seal(f.repo, f.cfg, only = @[""]), "non-empty")
      doAssert vaultBytes(f.repo) == before

    test "ambiguous tracked paths are rejected":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      var entries = loadManifest(f.repo, verifySig = true, cfg = f.cfg)
      entries[1].path = entries[0].path
      saveManifest(f.repo, entries, f.cfg, sealKey(f.cfg), envelope = true)
      let before = vaultBytes(f.repo)
      reject(proc() = seal(f.repo, f.cfg, only = @[f.paths[0]]), "ambiguous")
      doAssert vaultBytes(f.repo) == before

    test "an empty store does not silently accept a selector or prune keys":
      let repo = createTempDir("nimvault_selected_", "_empty")
      defer: removeDir(repo)
      let cfg = GpgConfig(recipient: keyId, root: repo / "plain")
      ensureVaultDir(repo)
      let plain = repo / "fixture-key.txt"
      writeFile(plain, "fixture-only key material")
      encryptFileTo(cfg, @[keyId], plain, keysPath(repo, cfg), sign = false)
      let before = vaultBytes(repo)
      reject(proc() = seal(repo, cfg, only = @["missing.txt"]), "Not in vault")
      doAssert vaultBytes(repo) == before

    test "selected manifest traversal is rejected before reading plaintext":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      var entries = loadManifest(f.repo, verifySig = true, cfg = f.cfg)
      entries[0].path = "../outside.txt"
      saveManifest(f.repo, entries, f.cfg, sealKey(f.cfg), envelope = true)
      let before = vaultBytes(f.repo)
      reject(proc() = seal(f.repo, f.cfg,
        only = @[f.repo / "outside.txt"]), "unsafe path")
      doAssert vaultBytes(f.repo) == before

    test "changed or unrecorded encryption settings require explicit full seal":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      var changed = f.cfg
      changed.wraps = @[]
      let before = vaultBytes(f.repo)
      reject(proc() = seal(f.repo, changed, only = @[f.paths[0]]),
             "unchanged recorded encryption settings")
      doAssert vaultBytes(f.repo) == before
      let entries = loadManifest(f.repo, verifySig = true, cfg = f.cfg)
      saveManifest(f.repo, entries, f.cfg, envelope = true)
      let withoutMarker = vaultBytes(f.repo)
      reject(proc() = seal(f.repo, f.cfg, only = @[f.paths[0]]),
             "unchanged recorded encryption settings")
      doAssert vaultBytes(f.repo) == withoutMarker

    test "selected blob repair does not repair unselected corruption":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      let first = entryFor(f, 0)
      let second = entryFor(f, 1)
      let firstBlob = findBlob(f.repo, f.cfg, first.id)
      let secondBlob = findBlob(f.repo, f.cfg, second.id)
      removeFile(firstBlob)
      writeFile(secondBlob, readFile(secondBlob) & "tamper")
      let unselectedCorrupt = readFile(secondBlob)
      seal(f.repo, f.cfg, only = @[f.paths[0]])
      doAssert fileExists(firstBlob)
      doAssert readFile(secondBlob) == unselectedCorrupt
      doAssert get(f.repo, f.paths[0], f.cfg) == "original:first file.txt"
      reject(proc() = discard get(f.repo, f.paths[1], f.cfg), "tampered")

    test "unsigned unselected records still fail signature verification":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      let other = entryFor(f, 2)
      let record = findEntryFile(f.repo, f.cfg, other.id)
      let plain = privateWorkDir()
      defer: removeDir(plain)
      let plainPath = plain / "entry.plain"
      writeFile(plainPath, decryptToString(f.cfg, record, true))
      encryptFileTo(f.cfg, recipientsFor(f.cfg, other.path), plainPath,
                     record, sign = false)
      writeFile(f.paths[0], "selected edit")
      let before = vaultBytes(f.repo)
      reject(proc() = seal(f.repo, f.cfg, only = @[f.paths[0]]), "signature")
      doAssert vaultBytes(f.repo) == before

    test "combined legacy records retain unselected values and payloads":
      let f = fixture(keyId, fingerprint, combined = true)
      defer: removeDir(f.repo)
      let second = entryFor(f, 1)
      let secondBlob = readFile(findBlob(f.repo, f.cfg, second.id))
      let marker = loadManifestMeta(f.repo, cfg = f.cfg).sealKey
      writeFile(f.paths[0], "selected legacy edit")
      removeFile(f.paths[1])
      seal(f.repo, f.cfg, only = @[f.paths[0]])
      doAssert not hasSplitEntries(f.repo)
      doAssert entryFor(f, 1) == second
      doAssert readFile(findBlob(f.repo, f.cfg, second.id)) == secondBlob
      doAssert loadManifestMeta(f.repo, cfg = f.cfg).sealKey == marker
      doAssert get(f.repo, f.paths[0], f.cfg) == "selected legacy edit"
      doAssert get(f.repo, f.paths[1], f.cfg) == "original:second.txt"
      unseal(f.repo, f.cfg, only = @[f.paths[1]])
      doAssert readFile(f.paths[1]) == "original:second.txt"

    test "bare seal retains the complete-store behavior":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      writeFile(f.paths[0], "first changed")
      writeFile(f.paths[1], "second changed")
      seal(f.repo, f.cfg)
      doAssert get(f.repo, f.paths[0], f.cfg) == "first changed"
      doAssert get(f.repo, f.paths[1], f.cfg) == "second changed"

    test "CLI positional paths select exact entries and preserve other changes":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      let binary = SourceRoot / "bin" / "nimvault"
      doAssert fileExists(binary), "build nimvault before the integration suite"
      let second = entryFor(f, 1)
      let originalSecondBlob = readFile(findBlob(f.repo, f.cfg, second.id))
      writeFile(f.paths[0], "CLI selected")
      writeFile(f.paths[1], "CLI unselected")
      let (output, code) = execCmdEx(binary.quoteShell & " seal " &
        f.paths[0].quoteShell & " --vault " & f.repo.quoteShell)
      doAssert code == 0, output
      doAssert "Sealed 1 selected file(s); 2 not selected." in output
      doAssert get(f.repo, f.paths[0], f.cfg) == "CLI selected"
      doAssert get(f.repo, f.paths[1], f.cfg) == "original:second.txt"
      doAssert readFile(findBlob(f.repo, f.cfg, second.id)) == originalSecondBlob
      doAssert readFile(f.paths[1]) == "CLI unselected"
      let (noop, noopCode) = execCmdEx(binary.quoteShell & " seal " &
        f.paths[0].quoteShell & " --vault " & f.repo.quoteShell)
      doAssert noopCode == 0, noop
      doAssert "1 selected file(s) already current." in noop

    test "public-only seal of one path leaves that entry untouched":
      let f = fixture(keyId, fingerprint)
      defer: removeDir(f.repo)
      writeFile(f.paths[0], "public-only must not reseal")
      writeFile(f.paths[1], "unselected edit")
      let before = vaultBytes(f.repo)
      putEnv("NIMVAULT_PUBLIC_ONLY", "1")
      seal(f.repo, f.cfg, only = @[f.paths[0]])
      delEnv("NIMVAULT_PUBLIC_ONLY")
      doAssert vaultBytes(f.repo) == before
      doAssert get(f.repo, f.paths[0], f.cfg) == "original:first file.txt"
      let binary = SourceRoot / "bin" / "nimvault"
      doAssert fileExists(binary), "build nimvault before the integration suite"
      let (output, code) = execCmdEx(binary.quoteShell & " seal " &
        f.paths[0].quoteShell & " --public-only --vault " & f.repo.quoteShell)
      doAssert code == 0, output
      doAssert "1 selected path(s) left untouched" in output
      doAssert vaultBytes(f.repo) == before

main()
