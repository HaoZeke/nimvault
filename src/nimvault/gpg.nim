## GPG encryption/decryption and recipient resolution.

import std/[os, osproc, strutils, strformat, streams]
import checksums/sha2

type
  NimvaultError* = object of CatchableError
  GpgConfig* = object
    recipient*: string
    root*: string  ## When non-empty, paths are relative to this dir (not ~/...)
    ## Which primitive encrypts blobs and the manifest. "gpg" keeps the
    ## long-standing behaviour where signing and encryption are one operation.
    ## "age" separates them: age has no signing, so authenticity moves to a
    ## detached signature over the manifest, whose recorded hashes already
    ## cover every blob.
    backend*: string        ## "gpg" (default) | "age"
    identity*: string       ## age identity file; required when backend is age
    signer*: string         ## "gpg" (default) | "ssh" | "none"
    signKey*: string        ## ssh private key used to sign the manifest
    allowedSigners*: string ## ssh allowed-signers file used to verify it
    signerIdentity*: string ## principal to match within allowed_signers

proc nvRaise*(msg: string) =
  ## Library-safe failure (no process exit). CLI catches and quits.
  raise newException(NimvaultError, msg)

var nvQuiet* {.threadvar.}: bool  ## When true, suppress banners/echo (C ABI / MCP in-process)

type VaultConfigFile* = tuple[recipient, root, backend, identity, signer,
                              signKey, allowedSigners, signerIdentity: string]

proc parseVaultConfig(configFile: string): VaultConfigFile =
  ## Parse .vault/config. Unknown keys are ignored so an older binary reading a
  ## newer vault fails on the crypto it cannot do, with a clear message, rather
  ## than on the config it does not recognise.
  if not fileExists(configFile):
    return
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
        of "backend": result.backend = val
        of "identity": result.identity = val
        of "signer": result.signer = val
        of "sign_key": result.signKey = val
        of "allowed_signers": result.allowedSigners = val
        of "signer_identity": result.signerIdentity = val
        else: discard

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
  nvRaise("FATAL: no GPG recipient found. Set via --recipient, NIMVAULT_GPG_RECIPIENT env, or .vault/config")

proc initGpgConfig*(cliRecipient: string, repo: string): GpgConfig =
  ## Build a GpgConfig by resolving recipient and root from the 3-tier chain.
  let configPath = repo / ".vault" / "config"
  let c = parseVaultConfig(configPath)
  var root = c.root
  if root == "repo":
    root = repo
  elif root.len > 0 and not root.isAbsolute:
    root = repo / root

  let backend = if getEnv("NIMVAULT_BACKEND").len > 0: getEnv("NIMVAULT_BACKEND")
                elif c.backend.len > 0: c.backend
                else: "gpg"

  # The signer defaults to whatever the backend can do on its own. gpg signs as
  # it encrypts, so it needs nothing further; age cannot sign at all, so a vault
  # using it must say how its manifest is to be vouched for rather than silently
  # ending up with no authenticity at all.
  let signer = if c.signer.len > 0: c.signer
               elif backend == "age": "ssh"
               else: "gpg"

  let identity = if getEnv("NIMVAULT_AGE_IDENTITY").len > 0: getEnv("NIMVAULT_AGE_IDENTITY")
                 else: c.identity

  # age recipients live in the config rather than the GPG env var, so only the
  # gpg backend consults the 3-tier chain that raises when it finds nothing.
  let recipient = if backend == "age":
                    if cliRecipient.len > 0: cliRecipient else: c.recipient
                  else:
                    resolveRecipient(cliRecipient, "NIMVAULT_GPG_RECIPIENT", c.recipient)

  result = GpgConfig(
    recipient: recipient,
    root: root,
    backend: backend,
    identity: identity,
    signer: signer,
    signKey: c.signKey,
    allowedSigners: c.allowedSigners,
    signerIdentity: c.signerIdentity,
  )

proc gpgEncrypt*(cfg: GpgConfig, inPath, outPath: string) =
  ## Encrypt and sign a file using GPG with the configured recipient.
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--trust-model", "always",
             "--sign", "-e", "-r", cfg.recipient,
             "--set-filename", "", "-o", outPath, inPath],
    options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: gpg encrypt failed (exit {code}):\n{output}")

proc gpgDecrypt*(inPath, outPath: string, verifySig = false) =
  ## Decrypt a GPG-encrypted file to a target path.
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
             "-d", "-o", outPath, inPath],
    options = {poUsePath})
  discard p.outputStream.readAll()
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: gpg decrypt failed (exit {code})\n{status}")
  if verifySig:
    if "BADSIG" in status or "ERRSIG" in status:
      nvRaise(&"FATAL: signature verification failed for {inPath}")
    if "GOODSIG" notin status:
      nvRaise(&"FATAL: missing signature on {inPath}. Pass --allow-unsigned to accept unsigned vaults.")

proc gpgDecryptToString*(inPath: string, verifySig = false): string =
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--status-fd", "2", "-d", inPath],
    options = {poUsePath})
  result = p.outputStream.readAll().strip()
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: gpg decrypt failed (exit {code})\n{status}")
  if verifySig:
    if "BADSIG" in status or "ERRSIG" in status:
      nvRaise(&"FATAL: signature verification failed for {inPath}")
    if "GOODSIG" notin status:
      nvRaise(&"FATAL: missing signature on {inPath}. Pass --allow-unsigned to accept unsigned vaults.")

proc gpgParallelism*(): int =
  let raw = getEnv("NIMVAULT_GPG_PARALLEL")
  if raw.len == 0:
    return 8
  try:
    result = parseInt(raw)
  except ValueError:
    return 8
  if result < 1: result = 1
  if result > 64: result = 64

proc sha256sum*(path: string): string =
  const chunk = 1024 * 1024
  var ctx = initSha_256()
  var f: File
  if not open(f, path, fmRead):
    nvRaise(&"FATAL: cannot open for hashing: {path}")
  defer: f.close()
  var buf = newString(chunk)
  while true:
    let n = f.readBuffer(addr buf[0], chunk)
    if n <= 0: break
    if n < chunk:
      buf.setLen(n)
      ctx.update(buf)
      break
    ctx.update(buf)
  let d = ctx.digest()
  for i in 0 ..< d.len:
    result.add toHex(int(d[i]), 2)
  result = result.toLowerAscii()

proc sha256sumBytes*(data: string): string =
  var ctx = initSha_256()
  ctx.update(data)
  let d = ctx.digest()
  for i in 0 ..< d.len:
    result.add toHex(int(d[i]), 2)
  result = result.toLowerAscii()
