## Integration tests for nimvault commands.
##
## Creates a temp git repo with a throwaway GPG key, runs full workflow:
## add -> list -> seal -> status -> unseal -> rm
## Also tests blob hash integrity and path safety.

import std/[os, osproc, strutils, strformat, tempfiles, posix, tables]
import nimvault/[gpg, manifest, commands, lock, crypto, dek]

proc setupTestGpgHome(): string =
  result = createTempDir("nimvault_int_", "_gpg")
  setFilePermissions(result, {fpUserRead, fpUserWrite, fpUserExec})
  putEnv("GNUPGHOME", result)
  let keyScript = result / "keygen.txt"
  writeFile(keyScript, """
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: NimVault IntTest
Name-Email: inttest@nimvault.local
Expire-Date: 0
%commit
""")
  let (output, code) = execCmdEx(&"gpg --batch --gen-key {keyScript.quoteShell}")
  doAssert code == 0, &"GPG keygen failed:\n{output}"

proc getTestKeyId(): string =
  let (output, code) = execCmdEx("gpg --list-keys --keyid-format long --with-colons inttest@nimvault.local")
  doAssert code == 0, &"GPG list-keys failed:\n{output}"
  for line in output.splitLines:
    if line.startsWith("pub:"):
      let parts = line.split(':')
      if parts.len > 4:
        return parts[4]
  doAssert false, "Could not find test key ID"

proc setupTestRepo(): string =
  result = createTempDir("nimvault_repo_", "_test")
  let (_, code) = execCmdEx("git init", workingDir = result)
  doAssert code == 0
  # Create initial commit so git rev-parse works
  writeFile(result / ".gitkeep", "")
  discard execCmdEx("git add . && git commit -m init", workingDir = result)

# Setup
let gpgHome = setupTestGpgHome()
let keyId = getTestKeyId()
let repo = setupTestRepo()
let cfg = GpgConfig(recipient: keyId)

# Create a test secret file inside the repo (simulating an absolute path target)
let secretDir = repo / "secrets"
createDir(secretDir)
let secretPath = secretDir / "api_key.txt"
writeFile(secretPath, "sk-test-12345-secret-key")

block addFile:
  add(repo, secretPath, cfg)
  let entries = loadManifest(repo)
  doAssert entries.len == 1, "Should have 1 entry after add"
  doAssert resolvePath(cfg, entries[0].path) == secretPath
  let blobPath = vaultDir(repo) / &"{entries[0].id}.gpg"
  doAssert fileExists(blobPath), "Blob file should exist"
  # v2: hash should be populated
  doAssert entries[0].hash.len == 64, "Blob hash should be SHA-256 (64 hex chars)"
  echo "PASS: add (with blob hash)"

block getSingleEntry:
  # `get` must return exactly the plaintext with nothing else on the stream:
  # its whole purpose is to be read by another program.
  let got = get(repo, secretPath, cfg, allowUnsigned = true)
  doAssert got == "sk-test-12345-secret-key", "get returned: " & got
  echo "PASS: get returns plaintext"

block getLeavesNothingBehind:
  # Unlike unseal, get must not materialise anything. Remove the plaintext and
  # confirm get still answers from the blob without recreating the file.
  let saved = readFile(secretPath)
  removeFile(secretPath)
  let got = get(repo, secretPath, cfg, allowUnsigned = true)
  doAssert got == saved, "get should read the blob, not the file"
  doAssert not fileExists(secretPath), "get must not write the entry to disk"
  writeFile(secretPath, saved)
  echo "PASS: get writes nothing to disk"

block getRejectsUnknownPath:
  var raised = false
  try:
    discard get(repo, repo / "secrets" / "nope.txt", cfg, allowUnsigned = true)
  except CatchableError:
    raised = true
  doAssert raised, "get should refuse a path that is not in the vault"
  echo "PASS: get refuses an untracked path"

block getDetectsTamperedBlob:
  # The integrity check is why get repeats unseal's guards rather than trusting
  # the blob: a caller reading one secret needs it as much as one reading all.
  let entries = loadManifest(repo)
  let blobPath = vaultDir(repo) / &"{entries[0].id}.gpg"
  let original = readFile(blobPath)
  writeFile(blobPath, original & "tamper")
  var raised = false
  try:
    discard get(repo, secretPath, cfg, allowUnsigned = false)
  except CatchableError:
    raised = true
  doAssert raised, "get should refuse a blob whose hash does not match"
  writeFile(blobPath, original)
  echo "PASS: get detects a tampered blob"

block unsealSelective:
  # Selective unseal must restore what was named and nothing else. Seal first
  # so the plaintext can be removed and its return observed.
  seal(repo, cfg)
  let secondPath = secretDir / "other.txt"
  writeFile(secondPath, "second-secret-value")
  add(repo, secondPath, cfg)
  seal(repo, cfg)

  let firstSaved = readFile(secretPath)
  removeFile(secretPath)
  removeFile(secondPath)

  unseal(repo, cfg, allowUnsigned = true, only = @[secretPath])
  doAssert fileExists(secretPath), "named entry should be restored"
  doAssert readFile(secretPath) == firstSaved
  doAssert not fileExists(secondPath), "unnamed entry must NOT be restored"
  echo "PASS: unseal restores only the named entry"

  unseal(repo, cfg, allowUnsigned = true)
  doAssert fileExists(secondPath), "bare unseal should restore everything"
  echo "PASS: bare unseal still restores all"

  # Leave the vault as this block found it: later blocks assert on the entry
  # count, so a fixture that adds an entry has to take it away again.
  remove(repo, secondPath, cfg)
  removeFile(secondPath)

block unsealSelectorMustMatch:
  # A selector matching nothing is an error: unsealing zero files and reporting
  # success is indistinguishable from having done the work.
  var raised = false
  try:
    unseal(repo, cfg, allowUnsigned = true, only = @[repo / "secrets" / "absent.txt"])
  except CatchableError:
    raised = true
  doAssert raised, "a selector matching nothing should raise"
  echo "PASS: unseal rejects a selector that matches nothing"

block unsealDirectorySelector:
  # Naming a directory restores everything beneath it.
  removeFile(secretPath)
  unseal(repo, cfg, allowUnsigned = true, only = @[secretDir])
  doAssert fileExists(secretPath), "directory selector should cover its entries"
  echo "PASS: unseal accepts a directory selector"

block listEntries:
  list(repo, cfg)
  echo "PASS: list (visual check above)"

block sealEntries:
  seal(repo, cfg)
  # Verify manifest is v2 with hashes
  let entries = loadManifest(repo)
  doAssert entries.len == 1
  doAssert entries[0].hash.len == 64, "Seal should produce v2 manifest with hashes"
  echo "PASS: seal (signed, v2 manifest)"

block statusCheck:
  status(repo, cfg)
  echo "PASS: status (visual check above)"

block unsealEntries:
  # Remove the plaintext, then unseal (with signature + hash verification)
  removeFile(secretPath)
  doAssert not fileExists(secretPath)
  unseal(repo, cfg)
  doAssert fileExists(secretPath), "Secret should be restored after unseal"
  doAssert readFile(secretPath) == "sk-test-12345-secret-key"
  echo "PASS: unseal round-trip (verified)"

block moveEntry:
  let newPath = secretDir / "api_key_moved.txt"
  move(repo, secretPath, newPath, cfg)
  let entries = loadManifest(repo)
  doAssert entries.len == 1
  doAssert resolvePath(cfg, entries[0].path) == newPath
  doAssert fileExists(newPath)
  doAssert not fileExists(secretPath)
  # Move back for rm test
  move(repo, newPath, secretPath, cfg)
  echo "PASS: move"

block removeEntry:
  remove(repo, secretPath, cfg)
  let entries = loadManifest(repo)
  doAssert entries.len == 0, "Should have 0 entries after rm"
  echo "PASS: rm"

# --- Root-relative mode tests (pixi_envs parity) ---
block rootRelativeWorkflow:
  ## With root set to repo, paths are stored relative to root and resolved back.
  let rootRepo = setupTestRepo()
  let rootCfg = GpgConfig(recipient: keyId, root: rootRepo)
  let rootSecretDir = rootRepo / "conda"
  createDir(rootSecretDir)
  let rootSecretPath = rootSecretDir / "CLAUDE.md"
  writeFile(rootSecretPath, "# project claude config")

  # Add using root-relative path
  add(rootRepo, rootSecretPath, rootCfg)
  var entries = loadManifest(rootRepo)
  doAssert entries.len == 1
  doAssert entries[0].path == "conda/CLAUDE.md", &"Expected relative path, got: {entries[0].path}"
  doAssert resolvePath(rootCfg, entries[0].path) == rootSecretPath
  doAssert entries[0].hash.len == 64, "Root-relative add should store blob hash"
  echo "PASS: root-relative add"

  # Seal and unseal round-trip
  seal(rootRepo, rootCfg)
  removeFile(rootSecretPath)
  doAssert not fileExists(rootSecretPath)
  unseal(rootRepo, rootCfg)
  doAssert fileExists(rootSecretPath)
  doAssert readFile(rootSecretPath) == "# project claude config"
  echo "PASS: root-relative seal/unseal"

  # Move within root
  let rootNewPath = rootSecretDir / "CLAUDE_moved.md"
  move(rootRepo, rootSecretPath, rootNewPath, rootCfg)
  entries = loadManifest(rootRepo)
  doAssert entries[0].path == "conda/CLAUDE_moved.md"
  move(rootRepo, rootNewPath, rootSecretPath, rootCfg)
  echo "PASS: root-relative move"

  # Remove
  remove(rootRepo, rootSecretPath, rootCfg)
  entries = loadManifest(rootRepo)
  doAssert entries.len == 0
  echo "PASS: root-relative rm"

  removeDir(rootRepo)
  echo "PASS: root-relative workflow (pixi_envs parity)"

# --- Directory support tests ---
block addDirectory:
  ## Test adding a directory recursively.
  let dirRepo = setupTestRepo()
  let dirCfg = GpgConfig(recipient: keyId)

  # Create a directory tree with multiple files
  let testDir = createTempDir("nimvault_testdir_", "_tmp")
  let subDir = testDir / "subdir"
  createDir(subDir)
  writeFile(testDir / "file1.txt", "content 1")
  writeFile(testDir / "file2.txt", "content 2")
  writeFile(subDir / "file3.txt", "content 3")
  writeFile(subDir / "file4.txt", "content 4")

  # Add the directory
  addDir(dirRepo, testDir, dirCfg)
  var entries = loadManifest(dirRepo)
  doAssert entries.len == 4, &"Should have 4 entries after addDir, got {entries.len}"
  echo "PASS: addDir (4 files)"

  # Verify all entries are files with hashes
  for e in entries:
    doAssert e.kind == ekFile, "All entries should be files"
    doAssert e.hash.len == 64, "All entries should have SHA-256 hashes"

  # Seal
  seal(dirRepo, dirCfg)
  entries = loadManifest(dirRepo)
  doAssert entries.len == 4
  echo "PASS: seal with directory entries"

  # Unseal and verify
  # First remove all plaintext files
  removeDir(testDir)
  createDir(testDir)
  doAssert not fileExists(testDir / "file1.txt")

  unseal(dirRepo, dirCfg)
  doAssert fileExists(testDir / "file1.txt")
  doAssert fileExists(testDir / "file2.txt")
  doAssert fileExists(subDir / "file3.txt")
  doAssert fileExists(subDir / "file4.txt")
  doAssert readFile(testDir / "file1.txt") == "content 1"
  doAssert readFile(subDir / "file3.txt") == "content 3"
  echo "PASS: unseal restores directory structure"

  # Remove directory from vault (recursive)
  proc removeDirFromVault(dir: string) =
    for kind, path in walkDir(dir, relative = false):
      case kind
      of pcFile, pcLinkToFile:
        remove(dirRepo, path, dirCfg)
      of pcDir, pcLinkToDir:
        removeDirFromVault(path)
      else:
        discard

  removeDirFromVault(testDir)

  entries = loadManifest(dirRepo)
  doAssert entries.len == 0, "Should have 0 entries after removing all files"
  echo "PASS: remove all directory files"

  # Cleanup
  removeDir(testDir)
  removeDir(dirRepo)
  echo "PASS: directory workflow"

# --- Path safety tests ---
block pathSafetyInUnseal:
  ## Verify that isPathSafe catches traversal attempts.
  let safeCfg = GpgConfig(recipient: keyId, root: "/tmp/fakerepo")
  doAssert isPathSafe(safeCfg, "secrets/key.txt"), "Normal path should pass"
  doAssert not isPathSafe(safeCfg, "../../etc/passwd"), "Traversal should fail"
  doAssert not isPathSafe(safeCfg, "../outside/file"), "Parent escape should fail"
  echo "PASS: path safety validation"

# --- Incremental seal ---
# These blocks own their fixture: the shared `repo` above is emptied by the
# directory teardown, and an incremental seal only means anything with entries.
let incRepo = setupTestRepo()
let incCfg = GpgConfig(recipient: keyId)
let incDir = incRepo / "secrets"
createDir(incDir)
let incA = incDir / "alpha.txt"
let incB = incDir / "beta.txt"
writeFile(incA, "alpha-secret-value")
writeFile(incB, "beta-secret-value")
add(incRepo, incA, incCfg)
add(incRepo, incB, incCfg)

proc incBlobs(): seq[(string, string, string)] =
  for e in loadManifest(incRepo):
    result.add((e.id, e.path, readFile(vaultDir(incRepo) / &"{e.id}.gpg")))

block sealSkipsUnchangedFiles:
  ## Encryption is not deterministic, so re-sealing an untouched file used to
  ## produce a different blob and a diff across the whole vault.
  seal(incRepo, incCfg)
  let before = incBlobs()
  doAssert before.len == 2, "fixture should hold two entries"

  seal(incRepo, incCfg)
  for (id, _, blob) in before:
    doAssert readFile(vaultDir(incRepo) / &"{id}.gpg") == blob,
      &"blob {id} changed although its plaintext did not"
  echo "PASS: re-seal leaves unchanged blobs byte for byte"

block sealRewritesOnlyTheChangedFile:
  let before = incBlobs()
  writeFile(incA, "alpha-secret-value-CHANGED")
  seal(incRepo, incCfg)

  var changed = 0
  for (id, path, blob) in before:
    let now = readFile(vaultDir(incRepo) / &"{id}.gpg")
    if resolvePath(incCfg, path) == incA:
      doAssert now != blob, "the edited file should have a fresh blob"
      changed.inc
    else:
      doAssert now == blob, &"untouched {path} should keep its blob"
  doAssert changed == 1, "exactly one blob should have been rewritten"
  echo "PASS: seal rewrites only the changed file"

block sealForceRewritesEverything:
  let before = incBlobs()
  seal(incRepo, incCfg, force = true)
  for (id, _, blob) in before:
    doAssert readFile(vaultDir(incRepo) / &"{id}.gpg") != blob,
      &"--force should have re-encrypted {id}"
  echo "PASS: --force re-encrypts every blob"

block sealRepairsMissingAndCorruptBlobs:
  ## A skip must not survive a blob that is gone or corrupted.
  seal(incRepo, incCfg)
  let entries = loadManifest(incRepo)
  let victim = vaultDir(incRepo) / &"{entries[0].id}.gpg"
  removeFile(victim)
  seal(incRepo, incCfg)
  doAssert fileExists(victim), "seal should re-create a missing blob"

  let tampered = vaultDir(incRepo) / &"{entries[1].id}.gpg"
  writeFile(tampered, readFile(tampered) & "tamper")
  let broken = readFile(tampered)
  seal(incRepo, incCfg)
  doAssert readFile(tampered) != broken,
    "seal should replace a blob whose hash no longer matches"
  echo "PASS: seal repairs missing and corrupted blobs"

block sealKeyTracksEncryptionTarget:
  ## Unchanged plaintext still owes a new blob when the recipient moves.
  let a = GpgConfig(recipient: "KEY-A", backend: "gpg", signer: "gpg")
  let b = GpgConfig(recipient: "KEY-B", backend: "gpg", signer: "gpg")
  doAssert sealKey(a) != sealKey(b), "a different recipient must change the key"
  doAssert sealKey(a) == sealKey(a), "the same config must be stable"

  var c = a
  c.backend = "age"
  doAssert sealKey(a) != sealKey(c), "a different backend must change the key"

  seal(incRepo, incCfg)
  let meta = loadManifestMeta(incRepo, cfg = incCfg)
  doAssert meta.sealKey == sealKey(incCfg), "manifest should record the seal key"
  echo "PASS: seal key tracks the encryption target"

block sealKeyChangeForcesFullReseal:
  ## The whole point of recording the key: a rotation must not be skipped.
  seal(incRepo, incCfg)
  let before = incBlobs()

  var rotated = incCfg
  rotated.signer = "none"
  doAssert sealKey(rotated) != sealKey(incCfg)
  seal(incRepo, rotated)
  for (id, _, blob) in before:
    doAssert readFile(vaultDir(incRepo) / &"{id}.gpg") != blob,
      &"a changed seal key must re-encrypt {id}"
  echo "PASS: a seal-key change re-encrypts everything"


block sealLeavesManifestAloneWhenNothingChanged:
  ## The manifest is encrypted and signed, so rewriting it is a change in its
  ## own right: a no-op seal would still leave a modified file in git.
  seal(incRepo, incCfg)
  let mpath = manifestPath(incRepo, incCfg)
  let before = readFile(mpath)
  seal(incRepo, incCfg)
  doAssert readFile(mpath) == before,
    "a seal that changed nothing must not rewrite the manifest"

  writeFile(incB, "beta-secret-value-CHANGED")
  seal(incRepo, incCfg)
  doAssert readFile(mpath) != before,
    "a real change must still be recorded"
  echo "PASS: no-op seal leaves the manifest untouched"

block vaultLockExcludesAnotherProcess:
  ## fcntl records are per process, so this has to fork to mean anything.
  let pid = fork()
  if pid == 0:
    var held = acquire(incRepo)
    sleep(1500)
    release(held)
    quit(0)
  doAssert pid > 0, "fork failed"
  sleep(400)          # let the child take the lock first

  var raised = false
  try:
    var mine = acquire(incRepo, timeoutMs = 300)
    release(mine)
  except CatchableError:
    raised = true
  var status: cint
  discard waitpid(pid, status, 0)
  doAssert raised, "a second process must not get the lock while it is held"

  # Once the holder is gone the lock is free again, with nothing to clean up.
  var after = acquire(incRepo, timeoutMs = 1000)
  release(after)
  echo "PASS: vault lock excludes another process"


block checkCatchesBlobManifestDesync:
  ## The failure this reproduces actually happened: a blob was committed
  ## without the manifest recording its hash. `status` compares plaintext and
  ## saw nothing wrong; the entry would only have failed at unseal time, on a
  ## machine where the plaintext no longer exists.
  seal(incRepo, incCfg)
  let clean = checkVault(incRepo, incCfg)
  doAssert clean.problems.len == 0, "a freshly sealed vault should be consistent"
  doAssert clean.checked == 2

  let entries = loadManifest(incRepo)
  let blob = vaultDir(incRepo) / &"{entries[0].id}.gpg"
  let good = readFile(blob)
  writeFile(blob, good & "drift")

  let drifted = checkVault(incRepo, incCfg)
  doAssert drifted.problems.len == 1, "check should flag the drifted blob"
  doAssert "does not match" in drifted.problems[0]

  # status is deliberately unchanged here: it answers a different question.
  doAssert "[in-sync]" in statusReport(incRepo, incCfg),
    "status compares plaintext and should still call this in-sync"

  writeFile(blob, good)
  doAssert checkVault(incRepo, incCfg).problems.len == 0

  removeFile(blob)
  let missing = checkVault(incRepo, incCfg)
  doAssert missing.problems.len == 1 and "no blob" in missing.problems[0]
  seal(incRepo, incCfg)
  doAssert checkVault(incRepo, incCfg).problems.len == 0,
    "seal should have rebuilt the missing blob"
  echo "PASS: check catches blob/manifest desync that status cannot"


# --- v6 envelope keys ---
block v6SealWrapsPayloadsUnderDataKeys:
  ## The recipient used to be baked into every blob, so adding a machine meant
  ## re-encrypting the whole vault. v6 puts a per-file data key in one small
  ## file encrypted to the recipients instead.
  seal(incRepo, incCfg)
  let keys = keyFiles(incRepo, incCfg)
  doAssert keys.len > 0, "seal should write a data-key file"

  let deks = loadDeks(incRepo, incCfg)
  let entries = loadManifest(incRepo)
  doAssert deks.len == entries.len, "every entry should have a data key"
  for e in entries:
    doAssert deks.hasKey(e.id), &"no data key for {e.path}"
    doAssert deks[e.id].len > 0

  # Distinct keys per file: a leak of one opens one.
  var seen: seq[string] = @[]
  for _, k in deks:
    doAssert k notin seen, "data keys must not be shared between entries"
    seen.add(k)
  echo "PASS: v6 seal wraps each payload under its own data key"

block v6RoundTrips:
  writeFile(incA, "alpha-v6-value")
  writeFile(incB, "beta-v6-value")
  seal(incRepo, incCfg)
  doAssert get(incRepo, incA, incCfg, allowUnsigned = true) == "alpha-v6-value"

  removeFile(incA)
  removeFile(incB)
  unseal(incRepo, incCfg, allowUnsigned = true)
  doAssert readFile(incA) == "alpha-v6-value"
  doAssert readFile(incB) == "beta-v6-value"
  echo "PASS: v6 payloads round-trip through get and unseal"

block v6CheckStillVerifiesBlobs:
  doAssert checkVault(incRepo, incCfg).problems.len == 0
  let entries = loadManifest(incRepo)
  let blob = vaultDir(incRepo) / &"{entries[0].id}.gpg"
  let good = readFile(blob)
  writeFile(blob, good & "drift")
  doAssert checkVault(incRepo, incCfg).problems.len == 1,
    "check must still catch a drifted v6 blob"
  writeFile(blob, good)
  echo "PASS: check works on enveloped blobs"

block rotateRewrapsKeysAndLeavesPayloadsAlone:
  ## The point of the format change: adding or rotating a recipient must not
  ## rewrite payloads.
  seal(incRepo, incCfg)
  let entries = loadManifest(incRepo)
  var before: seq[(string, string)] = @[]
  for e in entries:
    before.add((e.id, readFile(vaultDir(incRepo) / &"{e.id}.gpg")))
  let keysBefore = readFile(keyFiles(incRepo, incCfg)[0])
  let deksBefore = loadDeks(incRepo, incCfg)

  rotate(incRepo, incCfg)

  for (id, blob) in before:
    doAssert readFile(vaultDir(incRepo) / &"{id}.gpg") == blob,
      &"rewrapping must not touch payload {id}"
  doAssert readFile(keyFiles(incRepo, incCfg)[0]) != keysBefore,
    "the key file itself should have been rewritten"
  let deksAfter = loadDeks(incRepo, incCfg)
  for id, k in deksBefore:
    doAssert deksAfter[id] == k, "rewrapping must preserve the data keys"
  doAssert get(incRepo, incA, incCfg, allowUnsigned = true) == "alpha-v6-value"
  echo "PASS: rotate rewraps keys and leaves every payload alone"

block rekeyReencryptsEverything:
  let entries = loadManifest(incRepo)
  var before: seq[(string, string)] = @[]
  for e in entries:
    before.add((e.id, readFile(vaultDir(incRepo) / &"{e.id}.gpg")))
  let deksBefore = loadDeks(incRepo, incCfg)

  rotate(incRepo, incCfg, rekey = true)

  for (id, blob) in before:
    doAssert readFile(vaultDir(incRepo) / &"{id}.gpg") != blob,
      &"rekey must re-encrypt payload {id}"
  let deksAfter = loadDeks(incRepo, incCfg)
  for id, k in deksBefore:
    doAssert deksAfter[id] != k, "rekey must mint fresh data keys"
  doAssert get(incRepo, incA, incCfg, allowUnsigned = true) == "alpha-v6-value"
  doAssert checkVault(incRepo, incCfg).problems.len == 0
  echo "PASS: rekey re-encrypts every payload under fresh keys"

block staleDataKeysAreDropped:
  ## A key that outlives its entry is the means to read a blob nobody kept.
  let extra = incDir / "gamma.txt"
  writeFile(extra, "gamma-secret")
  add(incRepo, extra, incCfg)
  seal(incRepo, incCfg)
  let withGamma = loadDeks(incRepo, incCfg)
  doAssert withGamma.len == 3

  remove(incRepo, extra, incCfg)
  seal(incRepo, incCfg)
  doAssert loadDeks(incRepo, incCfg).len == 2,
    "seal should drop the data key for a removed entry"
  echo "PASS: data keys for removed entries are dropped"


# --- per-path recipient groups ---
block wrapRulesSelectRecipients:
  ## First matching rule wins and order is precedence, so a specific rule has
  ## to be able to sit above the general one.
  var c = GpgConfig(recipient: "DEFAULT")
  c.wraps = @["~/.ssh/**:LAPTOP", "**:LAPTOP,TERRA"]
  doAssert recipientsFor(c, "~/.ssh/id_ed25519") == @["LAPTOP"]
  doAssert recipientsFor(c, "~/.config/app.toml") == @["LAPTOP", "TERRA"]

  # A trailing slash means everything beneath.
  var c2 = GpgConfig(recipient: "DEFAULT")
  c2.wraps = @["~/.claude/:LAPTOP"]
  doAssert recipientsFor(c2, "~/.claude/settings.json") == @["LAPTOP"]
  doAssert recipientsFor(c2, "~/.other/settings.json") == @["DEFAULT"]

  # `*` does not span separators; `**` does.
  var c3 = GpgConfig(recipient: "DEFAULT")
  c3.wraps = @["~/x/*:A"]
  doAssert recipientsFor(c3, "~/x/one") == @["A"]
  doAssert recipientsFor(c3, "~/x/deep/one") == @["DEFAULT"]

  # No rules at all is the pre-groups behaviour.
  let plain = GpgConfig(recipient: "ONLY")
  doAssert recipientsFor(plain, "anything") == @["ONLY"]
  echo "PASS: wrap rules select recipients by path"

block groupIdDependsOnTheSetNotTheSpelling:
  doAssert groupId(@["B", "A"]) == groupId(@["A", "B"])
  doAssert groupId(@["A", "A", "B"]) == groupId(@["A", "B"])
  doAssert groupId(@["A"]) != groupId(@["A", "B"])
  echo "PASS: group id depends on the recipient set alone"

block groupsSplitKeyFilesAndGateReadability:
  ## The property the whole feature exists for: a machine holding only some
  ## recipients decrypts only the entries meant for it. Modelled here with a
  ## second GPG key, since that is what a second machine is.
  let otherHome = setupTestGpgHome()   # switches GNUPGHOME
  let otherKey = getTestKeyId()
  # Encrypting to another machine needs its public key here, which is the
  # real-world step too: exchange public keys, keep the private ones apart.
  let otherPub = otherHome / "other.pub"
  let (_, expCode) = execCmdEx(&"gpg --batch --yes --export --armor -o {otherPub.quoteShell} {otherKey}")
  doAssert expCode == 0, "exporting the other public key failed"
  putEnv("GNUPGHOME", gpgHome)
  let (impOut, impCode) = execCmdEx(&"gpg --batch --import {otherPub.quoteShell}")
  doAssert impCode == 0, "importing the other public key failed:\n" & impOut
  # Trust is not the point of this test; --trust-model always is already used.

  let gRepo = setupTestRepo()
  var gCfg = GpgConfig(recipient: keyId)
  let gDir = gRepo / "secrets"
  createDir(gDir)
  let mine = gDir / "mine.txt"
  let shared = gDir / "shared.txt"
  writeFile(mine, "laptop-only-secret")
  writeFile(shared, "shared-secret")
  add(gRepo, mine, gCfg)
  add(gRepo, shared, gCfg)

  # mine.txt to this key only; everything else to both.
  gCfg.wraps = @[&"**/mine.txt:{keyId}", &"**:{keyId},{otherKey}"]
  seal(gRepo, gCfg)

  # Two groups, so two key files.
  var keyFiles = 0
  for kind, path in walkDir(gRepo / ".vault"):
    if kind == pcFile and path.extractFilename.startsWith("keys."):
      keyFiles.inc
  doAssert keyFiles == 2, &"expected one key file per group, got {keyFiles}"

  # This machine holds keyId, so it reads both.
  doAssert loadDeks(gRepo, gCfg).len == 2
  doAssert get(gRepo, mine, gCfg, allowUnsigned = true) == "laptop-only-secret"

  # A machine holding only otherKey reads the shared entry and not the other.
  putEnv("GNUPGHOME", otherHome)
  let asOther = loadDeks(gRepo, gCfg)
  doAssert asOther.len == 1,
    &"the other machine should open exactly the shared group, got {asOther.len}"
  let sharedId = block:
    var found = ""
    putEnv("GNUPGHOME", gpgHome)
    for e in loadManifest(gRepo):
      if resolvePath(gCfg, e.path) == shared:
        found = e.id
    putEnv("GNUPGHOME", otherHome)
    found
  doAssert asOther.hasKey(sharedId), "the shared entry must be readable"

  # check needs no key at all, so it still works from the other machine.
  putEnv("GNUPGHOME", gpgHome)
  doAssert checkVault(gRepo, gCfg).problems.len == 0

  removeDir(gRepo)
  removeDir(otherHome)
  echo "PASS: groups split key files and gate what each machine can open"

removeDir(incRepo)

# Cleanup
removeDir(repo)
removeDir(gpgHome)
delEnv("GNUPGHOME")
echo "All integration tests passed."

# --- Directory security tests ---
block directorySecurityTests:
  ## Security tests for directory support.

  # Test path safety with nested traversal attempts
  let secCfg = GpgConfig(recipient: keyId, root: "/tmp/fakerepo")
  doAssert not isPathSafe(secCfg, "secrets/../../etc/passwd"), "Nested traversal should fail"
  doAssert not isPathSafe(secCfg, "a/b/../../../etc/passwd"), "Deep nested traversal should fail"
  doAssert isPathSafe(secCfg, "secrets/subdir/file.txt"), "Legitimate nested path should pass"
  echo "PASS: directory path safety"

  # Test empty directory rejection (CLI must exit non-zero; execCmdEx does not raise)
  let emptyDirRepo = setupTestRepo()
  let emptyTestDir = createTempDir("nimvault_empty_", "_dir")

  let (emptyOut, emptyCode) = execCmdEx(&"nimvault add-dir {emptyTestDir}",
                                        workingDir = emptyDirRepo)
  doAssert emptyCode != 0, "Should have rejected empty directory, got:\n" & emptyOut

  removeDir(emptyTestDir)
  removeDir(emptyDirRepo)
  echo "PASS: empty directory rejection"

  echo "PASS: all directory security tests"
