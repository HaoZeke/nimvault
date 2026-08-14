## age encryption and ssh signing, the pair that makes a vault readable without
## a person present.
##
## GPG fuses the two: `--sign -e` produces one blob and the signature is read
## back off the status stream while decrypting. age does not sign at all, so
## moving to it is a change of trust model rather than a substitution.
##
## The model that replaces it is the one the manifest already implies. Every
## entry carries a SHA-256 of its blob, and `unseal` and `get` check it before
## decrypting anything. Authenticity therefore only has to be established once,
## over the manifest; the hashes inside it cover the blobs. That makes a
## detached signature over the manifest sufficient, and per-blob signatures
## redundant.
##
## Signing uses `ssh-keygen -Y`, which verifies against an allowed-signers file
## and needs no agent when the key has no passphrase. That is what a timer at
## 04:00 requires: GPG's alternative is an agent whose cache expires, which
## fails silently on some later morning.

import std/[os, osproc, streams, strformat, strutils]
from ./gpg import GpgConfig, nvRaise

const
  ageBins = ["age", "rage"]        ## rage is a drop-in; prefer whichever exists
  sshKeygenBin = "ssh-keygen"

proc ageBinary*(): string =
  ## Resolve an age implementation once, so a missing binary is reported as
  ## itself rather than as a decryption failure further down.
  for b in ageBins:
    if findExe(b).len > 0:
      return b
  nvRaise("FATAL: no age binary found (looked for: " & ageBins.join(", ") & ")")

proc ageKeygenBinary*(): string =
  ## `age-keygen` ships beside `age`, `rage-keygen` beside `rage`.
  for b in ["age-keygen", "rage-keygen"]:
    if findExe(b).len > 0:
      return b
  nvRaise("FATAL: no age-keygen binary found (needed to mint a data key)")

proc ageRecipientForIdentity*(identity: string): string =
  ## Public recipient for an `AGE-SECRET-KEY-...` identity, so a payload can be
  ## encrypted under a data key the vault holds privately. The identity goes in
  ## on a pipe rather than a file so it never lands on disk unencrypted.
  let p = startProcess(ageKeygenBinary(), args = @["-y"],
                       options = {poUsePath, poStdErrToStdOut})
  p.inputStream.write(identity & "\n")
  p.inputStream.close()
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: age-keygen -y failed (exit {code}):\n{output}")
  for line in output.splitLines:
    let s = line.strip()
    if s.startsWith("age1"):
      return s
  nvRaise("FATAL: age-keygen -y produced no recipient")

proc expandTilde(p: string): string =
  if p.startsWith("~/"): getHomeDir() / p[2 .. ^1] else: p

proc ageIdentityPath*(cfg: GpgConfig): string =
  ## The identity is what makes decryption unattended, so its absence is worth
  ## a specific error: without it every read fails with an opaque age message.
  if cfg.identity.len == 0:
    nvRaise("FATAL: backend is age but no identity is configured.\n" &
            "  Set `identity = <path>` in .vault/config or NIMVAULT_AGE_IDENTITY.")
  result = expandTilde(cfg.identity)
  if not fileExists(result):
    nvRaise(&"FATAL: age identity not found: {result}")

proc ageEncrypt*(cfg: GpgConfig, inPath, outPath: string) =
  ## Encrypt to the configured recipient. No signature is produced here; the
  ## manifest signature covers this blob through its recorded hash.
  if cfg.recipient.len == 0:
    nvRaise("FATAL: no age recipient configured")
  let p = startProcess(ageBinary(),
    args = @["-r", cfg.recipient, "-o", outPath, inPath],
    options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: age encrypt failed (exit {code}):\n{output}")

proc ageDecrypt*(cfg: GpgConfig, inPath, outPath: string) =
  let ident = ageIdentityPath(cfg)
  let p = startProcess(ageBinary(),
    args = @["-d", "-i", ident, "-o", outPath, inPath],
    options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: age decrypt failed (exit {code}):\n{output}")

proc ageDecryptToString*(cfg: GpgConfig, inPath: string): string =
  let ident = ageIdentityPath(cfg)
  let p = startProcess(ageBinary(),
    args = @["-d", "-i", ident, inPath],
    options = {poUsePath})
  result = p.outputStream.readAll()
  let err = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: age decrypt failed (exit {code}):\n{err}")

## --- detached signing over the manifest ---

proc sshSign*(cfg: GpgConfig, path: string) =
  ## Write `<path>.sig`. The namespace is fixed so a signature made for this
  ## tool cannot be replayed as one made for git or anything else using the
  ## same key.
  if cfg.signKey.len == 0:
    nvRaise("FATAL: signer is ssh but no sign_key is configured")
  let key = expandTilde(cfg.signKey)
  if not fileExists(key):
    nvRaise(&"FATAL: ssh signing key not found: {key}")
  # Remove any previous signature first. Both `add` and `seal` save the
  # manifest, and age encryption is non-deterministic, so the second save
  # produces different ciphertext from the first. A signature left in place
  # from the earlier save then describes content that no longer exists, and the
  # vault fails to verify while every individual command reports success.
  let sigPath = path & ".sig"
  if fileExists(sigPath):
    removeFile(sigPath)

  let p = startProcess(sshKeygenBin,
    args = @["-Y", "sign", "-f", key, "-n", "nimvault", path],
    options = {poUsePath, poStdErrToStdOut})
  # ssh-keygen reads a passphrase from stdin when it wants one. With a pipe on
  # the other end and nobody closing it, an unencrypted key still leaves the
  # process waiting on input that never arrives, and the seal hangs with the
  # signature half written. Closing it turns that into an immediate, reportable
  # failure instead.
  p.inputStream.close()
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: ssh-keygen sign failed (exit {code}):\n{output}")
  # A zero exit with no signature on disk would leave an unverifiable vault
  # that reported success, which is the failure this whole path exists to prevent.
  if not fileExists(sigPath):
    nvRaise(&"FATAL: ssh-keygen reported success but wrote no signature at {sigPath}")

proc sshVerify*(cfg: GpgConfig, path: string) =
  ## Verify `<path>.sig` against the allowed-signers file. A missing signature
  ## is a failure, not a skip: an unsigned manifest is exactly what an attacker
  ## who replaced it would produce.
  let sig = path & ".sig"
  if not fileExists(sig):
    nvRaise(&"FATAL: missing signature for {path}.\n" &
            "  Pass --allow-unsigned to accept an unsigned vault.")
  if cfg.allowedSigners.len == 0:
    nvRaise("FATAL: signer is ssh but no allowed_signers is configured")
  let allowed = expandTilde(cfg.allowedSigners)
  if not fileExists(allowed):
    nvRaise(&"FATAL: allowed_signers not found: {allowed}")
  if cfg.signerIdentity.len == 0:
    nvRaise("FATAL: signer is ssh but no signer_identity is configured")

  let p = startProcess(sshKeygenBin,
    args = @["-Y", "verify", "-f", allowed, "-I", cfg.signerIdentity,
             "-n", "nimvault", "-s", sig],
    options = {poUsePath, poStdErrToStdOut})
  p.inputStream.write(readFile(path))
  p.inputStream.close()
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: signature verification failed for {path}:\n{output}")
