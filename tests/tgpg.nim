## Tests for nimvault/gpg: encrypt/decrypt cycle, recipient resolution.
##
## Requires GPG. Creates a throwaway key for testing.

import std/[os, osproc, strutils, strformat, tempfiles]
import nimvault/gpg
from nimvault/crypto import decryptManyToString

proc setupTestGpgHome(): string =
  ## Create a temporary GNUPGHOME with a throwaway key.
  result = createTempDir("nimvault_test_", "_gpg")
  setFilePermissions(result, {fpUserRead, fpUserWrite, fpUserExec})
  putEnv("GNUPGHOME", result)
  # Generate a throwaway key (no passphrase, no expiry)
  let keyScript = result / "keygen.txt"
  writeFile(keyScript, """
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: NimVault Test
Name-Email: test@nimvault.local
Expire-Date: 0
%commit
""")
  let (output, code) = execCmdEx(&"gpg --batch --gen-key {keyScript.quoteShell}")
  doAssert code == 0, &"GPG keygen failed:\n{output}"

proc getTestKeyId(gpgHome: string): string =
  let (output, code) = execCmdEx("gpg --list-keys --keyid-format long --with-colons test@nimvault.local")
  doAssert code == 0, &"GPG list-keys failed:\n{output}"
  for line in output.splitLines:
    if line.startsWith("pub:"):
      let parts = line.split(':')
      if parts.len > 4:
        return parts[4]
  doAssert false, "Could not find test key ID"

proc cleanupTestGpgHome(path: string) =
  removeDir(path)
  delEnv("GNUPGHOME")

# Run tests
let gpgHome = setupTestGpgHome()
let keyId = getTestKeyId(gpgHome)

block resolveRecipientCli:
  ## CLI value takes priority over env and config.
  let r = resolveRecipient("AABBCCDD", "NIMVAULT_GPG_RECIPIENT", "CONFIGKEY456")
  doAssert r == "AABBCCDD"
  echo "PASS: resolveRecipient CLI priority"

block resolveRecipientEnv:
  ## Env var used when CLI is empty.
  putEnv("NIMVAULT_GPG_RECIPIENT", "ENVKEY123")
  let r = resolveRecipient("", "NIMVAULT_GPG_RECIPIENT", "CONFIGKEY456")
  doAssert r == "ENVKEY123"
  delEnv("NIMVAULT_GPG_RECIPIENT")
  echo "PASS: resolveRecipient env fallback"

block resolveRecipientConfig:
  ## Config recipient used when CLI and env are empty.
  delEnv("NIMVAULT_GPG_RECIPIENT")
  let r = resolveRecipient("", "NIMVAULT_GPG_RECIPIENT", "CONFIGKEY456")
  doAssert r == "CONFIGKEY456"
  echo "PASS: resolveRecipient config fallback"

block initGpgConfigFromFile:
  ## initGpgConfig parses .vault/config and resolves recipient + root.
  let tmpDir = createTempDir("nimvault_cfg_", "_test")
  let vaultDir = tmpDir / ".vault"
  createDir(vaultDir)
  writeFile(vaultDir / "config", "# vault config\nrecipient = 9CCCE36402CB49A6\nroot = repo\n")
  delEnv("NIMVAULT_GPG_RECIPIENT")
  let cfg = initGpgConfig("", tmpDir)
  doAssert cfg.recipient == "9CCCE36402CB49A6"
  doAssert cfg.root == tmpDir  # "repo" expands to the repo path
  removeDir(tmpDir)
  echo "PASS: initGpgConfig from config file"

block encryptDecryptCycle:
  ## Encrypt (signed) then decrypt with verification, verify round-trip.
  let cfg = GpgConfig(recipient: keyId)
  let tmpDir = createTempDir("nimvault_ed_", "_test")
  let plainIn = tmpDir / "secret.txt"
  let encrypted = tmpDir / "secret.gpg"
  let plainOut = tmpDir / "secret_out.txt"
  let testContent = "Hello, nimvault! This is a test.\nLine two."

  writeFile(plainIn, testContent)
  gpgEncrypt(cfg, plainIn, encrypted)
  doAssert fileExists(encrypted), "Encrypted file should exist"

  gpgDecrypt(cfg, encrypted, plainOut, verifySig = true)
  doAssert fileExists(plainOut), "Decrypted file should exist"
  doAssert readFile(plainOut) == testContent, "Round-trip content mismatch"

  removeDir(tmpDir)
  echo "PASS: encrypt/decrypt cycle (signed)"

block decryptToString:
  ## gpgDecryptToString returns content directly with signature verification.
  let cfg = GpgConfig(recipient: keyId)
  let tmpDir = createTempDir("nimvault_ds_", "_test")
  let plainIn = tmpDir / "data.txt"
  let encrypted = tmpDir / "data.gpg"
  let testContent = "decrypt-to-string test content"

  writeFile(plainIn, testContent)
  gpgEncrypt(cfg, plainIn, encrypted)
  let result = gpgDecryptToString(cfg, encrypted, verifySig = true)
  doAssert result == testContent, "gpgDecryptToString content mismatch"

  removeDir(tmpDir)
  echo "PASS: gpgDecryptToString (verified)"

block validSigBindsThePrimaryKey:
  ## The tenth VALIDSIG field is the primary key; the first is the signing
  ## subkey. Pinning compares the primary key.
  let status = "[GNUPG:] NEWSIG\n" &
    "[GNUPG:] GOODSIG 0123456789ABCDEF Someone\n" &
    "[GNUPG:] VALIDSIG aaaa1111 2026-10-21 1792540800 0 4 0 1 10 00 bbbb2222\n"
  doAssert validSigners(status) == @["BBBB2222"]
  doAssert gpgSignerProblem(status, "rec", @["BBBB2222"]) == ""
  doAssert "not a key this vault is configured for" in
    gpgSignerProblem(status, "rec", @["AAAA1111"])
  doAssert "signature verification failed" in
    gpgSignerProblem("[GNUPG:] GOODSIG X\n", "rec", @["BBBB2222"])
  let cfg = GpgConfig(recipient: "A1", wraps: @["~/x/**:B2,A1", "**: C3 "])
  doAssert vaultSignerSpecs(cfg) == @["A1", "B2", "C3"]
  echo "PASS: VALIDSIG pins the primary key"

block sha256sumTest:
  let tmpDir = createTempDir("nimvault_sha_", "_test")
  let f = tmpDir / "hashme.txt"
  writeFile(f, "test content for hashing\n")
  let h = sha256sum(f)
  doAssert h.len == 64, "SHA-256 hex should be 64 chars"
  for c in h:
    doAssert c in {'0'..'9', 'a'..'f'}, "SHA-256 should be lowercase hex"
  # Verify deterministic
  let h2 = sha256sum(f)
  doAssert h == h2, "SHA-256 should be deterministic"
  removeDir(tmpDir)
  echo "PASS: sha256sum"

block decryptManyKeepsOrderAndReportsFailures:
  ## Twenty records decrypt four at a time, in the order asked; a file gpg
  ## cannot open comes back as its message instead of raising.
  let tmpDir = createTempDir("nimvault_many_", "_test")
  let cfg = GpgConfig(recipient: keyId)
  putEnv("NIMVAULT_GPG_PARALLEL", "4")
  var paths: seq[string] = @[]
  for i in 0 ..< 20:
    let plain = tmpDir / &"r{i}.txt"
    writeFile(plain, &"record {i}\n")
    let enc = tmpDir / &"r{i}.gpg"
    gpgEncrypt(cfg, plain, enc)
    paths.add(enc)
  let junk = tmpDir / "junk.gpg"
  writeFile(junk, "not a gpg file\n")
  paths.insert(junk, 7)
  let got = decryptManyToString(cfg, paths, verifySig = true)
  doAssert got.len == 21
  for i, path in paths:
    if path == junk:
      doAssert got[i].plain.len == 0 and "gpg decrypt failed" in got[i].err, got[i].err
    else:
      let n = if i < 7: i else: i - 1
      doAssert got[i].err.len == 0, got[i].err
      doAssert got[i].plain == &"record {n}\n", got[i].plain
  delEnv("NIMVAULT_GPG_PARALLEL")
  removeDir(tmpDir)
  echo "PASS: decryptManyToString order and failures"

cleanupTestGpgHome(gpgHome)
echo "All GPG tests passed."
