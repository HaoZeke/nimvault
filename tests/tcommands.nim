## Integration tests for nimvault commands.
##
## Creates a temp git repo with a throwaway GPG key, runs full workflow:
## add -> list -> seal -> status -> unseal -> rm
## Also tests blob hash integrity and path safety.

import std/[os, osproc, strutils, strformat, tempfiles]
import nimvault/[gpg, manifest, commands]

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
