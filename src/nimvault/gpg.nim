## GPG encryption/decryption and recipient resolution.

import std/[os, osproc, strutils, strformat, streams]

type
  GpgConfig* = object
    recipient*: string
    root*: string  ## When non-empty, paths are relative to this dir (not ~/...)

proc parseVaultConfig(configFile: string): tuple[recipient, root: string] =
  ## Parse .vault/config for recipient and root keys.
  if not fileExists(configFile):
    return ("", "")
  for line in lines(configFile):
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('=', maxsplit = 1)
    if parts.len == 2:
      let key = parts[0].strip()
      let val = parts[1].strip()
      if val.len > 0:
        case key
        of "recipient": result.recipient = val
        of "root": result.root = val

proc resolveRecipient*(cli, env, configRecipient: string): string =
  ## 3-tier recipient lookup:
  ## 1. CLI --recipient flag
  ## 2. NIMVAULT_GPG_RECIPIENT env var
  ## 3. value from .vault/config
  if cli.len > 0:
    return cli
  let envVal = getEnv(env)
  if envVal.len > 0:
    return envVal
  if configRecipient.len > 0:
    return configRecipient
  stderr.writeLine "FATAL: no GPG recipient found"
  stderr.writeLine "  Set via --recipient, NIMVAULT_GPG_RECIPIENT env, or .vault/config"
  quit 1

proc initGpgConfig*(cliRecipient: string, repo: string): GpgConfig =
  ## Build a GpgConfig by resolving recipient and root from the 3-tier chain.
  let configPath = repo / ".vault" / "config"
  let (cfgRecipient, cfgRoot) = parseVaultConfig(configPath)
  var root = cfgRoot
  if root == "repo":
    root = repo
  elif root.len > 0 and not root.isAbsolute:
    root = repo / root
  result = GpgConfig(
    recipient: resolveRecipient(cliRecipient, "NIMVAULT_GPG_RECIPIENT", cfgRecipient),
    root: root,
  )

proc gpgEncrypt*(cfg: GpgConfig, inPath, outPath: string) =
  ## Encrypt and sign a file using GPG with the configured recipient.
  ## Uses direct process invocation (no shell) to prevent command injection.
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--trust-model", "always",
             "--sign", "-e", "-r", cfg.recipient,
             "--set-filename", "", "-o", outPath, inPath],
    options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    stderr.writeLine &"FATAL: gpg encrypt failed (exit {code}):\n{output}"
    quit 1

proc gpgDecrypt*(inPath, outPath: string, verifySig = false) =
  ## Decrypt a GPG-encrypted file to a target path.
  ## When verifySig is true, warns on missing signatures and fails on bad ones.
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
             "-d", "-o", outPath, inPath],
    options = {poUsePath})
  discard p.outputStream.readAll()  # empty with -o
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    stderr.writeLine &"FATAL: gpg decrypt failed (exit {code})"
    stderr.writeLine status
    quit 1
  if verifySig:
    if "BADSIG" in status or "ERRSIG" in status:
      stderr.writeLine &"FATAL: signature verification failed for {inPath}"
      stderr.writeLine "  The file may have been tampered with."
      quit 1
    if "GOODSIG" notin status:
      stderr.writeLine &"WARNING: no signature on {inPath}"
      stderr.writeLine "  Run 'nimvault seal' to re-encrypt with signatures."

proc gpgDecryptToString*(inPath: string, verifySig = false): string =
  ## Decrypt a GPG-encrypted file and return contents as a string.
  ## Reads stdout for content and stderr for signature status.
  ## Pipe-safe for typical vault entries (< 64KB).
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--status-fd", "2", "-d", inPath],
    options = {poUsePath})
  result = p.outputStream.readAll().strip()
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    stderr.writeLine &"FATAL: gpg decrypt failed (exit {code})"
    stderr.writeLine status
    quit 1
  if verifySig:
    if "BADSIG" in status or "ERRSIG" in status:
      stderr.writeLine &"FATAL: signature verification failed for {inPath}"
      stderr.writeLine "  The file may have been tampered with."
      quit 1
    if "GOODSIG" notin status:
      stderr.writeLine &"WARNING: no signature on {inPath}"
      stderr.writeLine "  Run 'nimvault seal' to re-encrypt with signatures."

proc sha256sum*(path: string): string =
  ## Returns hex SHA-256 digest of a file.
  let p = startProcess("sha256sum", args = @[path],
    options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    stderr.writeLine &"FATAL: sha256sum failed for {path}\n{output}"
    quit 1
  result = output.strip().split(' ')[0]
