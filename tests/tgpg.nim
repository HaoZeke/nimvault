## Tests for nimvault/gpg: encrypt/decrypt cycle, recipient resolution.
##
## Requires GPG. Creates a throwaway key for testing.

import std/[os, osproc, strutils, strformat, tempfiles]
import nimvault/gpg

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
  writeFile(vaultDir / "config", "# vault config\nrecipient = CONFIGKEY456\nroot = repo\n")
  delEnv("NIMVAULT_GPG_RECIPIENT")
  let cfg = initGpgConfig("", tmpDir)
  doAssert cfg.recipient == "CONFIGKEY456"
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

  gpgDecrypt(encrypted, plainOut, verifySig = true)
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
  let result = gpgDecryptToString(encrypted, verifySig = true)
  doAssert result == testContent, "gpgDecryptToString content mismatch"

  removeDir(tmpDir)
  echo "PASS: gpgDecryptToString (verified)"

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

cleanupTestGpgHome(gpgHome)
echo "All GPG tests passed."
