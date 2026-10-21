## GPG encryption/decryption and recipient resolution.

import std/[os, osproc, strutils, strformat, streams]
import checksums/sha2

type
  NimvaultError* = object of CatchableError
    code*: int     ## Process exit. 1 operational, 2 tamper or unhealthy, 3 no prompt.
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
    wraps*: seq[string]     ## `<glob>:<recipient>[,...]` rules, in file order
    publicOnly*: bool       ## Encrypt to public keys and do not touch a secret key.

proc nvRaise*(msg: string, code = 1) =
  ## Library-safe failure (no process exit). CLI catches and quits with `code`.
  ## A zero code would look like success, so an unset field still exits 1.
  let e = newException(NimvaultError, msg)
  e.code = if code <= 0: 1 else: code
  raise e

var nvQuiet* {.threadvar.}: bool  ## When true, suppress banners/echo (C ABI / MCP in-process)
var nvNonInteractive* {.threadvar.}: bool
  ## Refuse pinentry. A missing passphrase or secret key is an error, not a prompt.

var secretKeyCache {.threadvar.}: tuple[home: string, known, present: bool]

proc pinentryInsert*(args: var seq[string]) =
  ## `--batch` alone still starts pinentry when a secret key is locked.
  ## `--pinentry-mode error` makes that a fast failure instead of a hang.
  if not nvNonInteractive:
    return
  var i = 0
  while i < args.len:
    if args[i] == "--batch":
      args.insert("--pinentry-mode", i + 1)
      args.insert("error", i + 2)
      return
    inc i
  args = @["--pinentry-mode", "error"] & args

proc gpgFailureCode*(output: string): int =
  ## Non-interactive callers need a distinct code when gpg wanted a human.
  if not nvNonInteractive:
    return 1
  let l = output.toLowerAscii
  if "no secret key" in l or "pinentry" in l or "inappropriate ioctl" in l or
     "cancelled" in l or "canceled" in l or "unusable secret key" in l or
     "signing failed" in l or "batchmode" in l:
    return 3
  return 1

proc gpgSecretKeyPresent*(): bool =
  ## True when this GNUPGHOME holds a secret key. Listing does not unlock it.
  ## Cached per home: add and seal ask more than once, and a test switches homes.
  let home = getEnv("GNUPGHOME")
  if secretKeyCache.known and secretKeyCache.home == home:
    return secretKeyCache.present
  var present = false
  if findExe("gpg").len > 0:
    let p = startProcess("gpg",
      args = @["--batch", "--pinentry-mode", "error",
               "--list-secret-keys", "--with-colons"],
      options = {poUsePath, poStdErrToStdOut})
    let output = p.outputStream.readAll()
    discard p.waitForExit()
    p.close()
    for line in output.splitLines:
      if line.startsWith("sec:") or line.startsWith("ssb:"):
        present = true
        break
  secretKeyCache = (home, true, present)
  present

proc ageIdentityPresent(cfg: GpgConfig): bool =
  ## The age identity is the decrypt key. A configured path that is not on
  ## this machine is the same as no key: a CI writer often has the recipient
  ## in `.vault/config` and nothing else.
  if cfg.identity.len == 0:
    return false
  var p = cfg.identity
  if p.startsWith("~/"):
    p = getHomeDir() / p[2 .. ^1]
  fileExists(p)

proc publicKeyOnly*(cfg: GpgConfig): bool =
  ## Encrypt to public keys and do not decrypt or sign.
  ##
  ## gpg signs in the same operation as `-e`, so a home with no secret key
  ## cannot produce a signed record. age does not sign; the ssh key does, and
  ## the identity file is what decrypts. No identity file is that same case.
  ## `--public-only` forces it when a decrypt key is present and must not be used.
  if cfg.publicOnly:
    return true
  if cfg.backend == "age":
    return not ageIdentityPresent(cfg)
  not gpgSecretKeyPresent()

type VaultConfigFile* = tuple[recipient, root, backend, identity, signer,
                              signKey, allowedSigners, signerIdentity: string,
                              wraps: seq[string]]
  ## `wraps` keeps `wrap = <glob>:<recipient>[,<recipient>...]` lines in file
  ## order, because the rule that matches first decides and order is therefore
  ## meaning, not formatting.

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
      if val.len == 0:
        continue
      if '\n' in val or '\r' in val:
        nvRaise(&"FATAL: {key} in .vault/config must be a single line")
      case key
      of "recipient":
        if result.recipient.len > 0 and result.recipient != val:
          nvRaise("FATAL: .vault/config has more than one recipient line")
        result.recipient = val
      of "root":
        if result.root.len > 0 and result.root != val:
          nvRaise("FATAL: .vault/config has more than one root line")
        result.root = val
      of "backend":
        if result.backend.len > 0 and result.backend != val:
          nvRaise("FATAL: .vault/config has more than one backend line")
        result.backend = val
      of "identity": result.identity = val
      of "signer": result.signer = val
      of "sign_key": result.signKey = val
      of "allowed_signers": result.allowedSigners = val
      of "signer_identity": result.signerIdentity = val
      of "wrap": result.wraps.add(val)
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
    wraps: c.wraps,
  )

proc gpgStatusHas*(status, token: string): bool =
  ## True when a `[GNUPG:] TOKEN` field is present. A UID that happens
  ## to contain the letters GOODSIG is not a status token.
  let prefix = "[GNUPG:] " & token
  for line in status.splitLines:
    let s = line.strip()
    if s == prefix:
      return true
    if s.startsWith(prefix) and s.len > prefix.len and s[prefix.len] in {' ', '\t'}:
      return true

proc gpgEncrypt*(cfg: GpgConfig, inPath, outPath: string) =
  ## Encrypt and sign a file using GPG with the configured recipient.
  if cfg.recipient.len == 0 or cfg.recipient[0] == '-' or
     '\n' in cfg.recipient or '\r' in cfg.recipient or '\0' in cfg.recipient:
    nvRaise("FATAL: invalid recipient")
  var args = @[
    "--batch", "--yes", "--quiet", "--no-options", "--no-encrypt-to",
    "--trust-model", "always",
    "--sign", "-e", "--recipient=" & cfg.recipient,
    "--set-filename", "", "-o", outPath, "--", inPath]
  pinentryInsert(args)
  let p = startProcess("gpg", args = args,
    options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: gpg encrypt failed (exit {code}):\n{output}",
            gpgFailureCode(output))

proc gpgDecrypt*(inPath, outPath: string, verifySig = false) =
  ## Decrypt a GPG-encrypted file to a target path.
  var args = @[
    "--batch", "--yes", "--quiet", "--status-fd", "2",
    "-d", "-o", outPath, "--", inPath]
  pinentryInsert(args)
  let p = startProcess("gpg", args = args, options = {poUsePath})
  discard p.outputStream.readAll()
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  if verifySig and (gpgStatusHas(status, "BADSIG") or gpgStatusHas(status, "ERRSIG")):
    nvRaise(&"FATAL: signature verification failed for {inPath}")
  if code != 0:
    nvRaise(&"FATAL: gpg decrypt failed (exit {code})\n{status}",
            gpgFailureCode(status))
  if verifySig and not gpgStatusHas(status, "GOODSIG"):
    nvRaise(&"FATAL: missing signature on {inPath}. Pass --allow-unsigned to accept unsigned vaults.")

proc gpgDecryptToString*(inPath: string, verifySig = false): string =
  var args = @[
    "--batch", "--yes", "--quiet", "--status-fd", "2", "-d", "--", inPath]
  pinentryInsert(args)
  let p = startProcess("gpg", args = args, options = {poUsePath})
  result = p.outputStream.readAll()
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  if verifySig and (gpgStatusHas(status, "BADSIG") or gpgStatusHas(status, "ERRSIG")):
    nvRaise(&"FATAL: signature verification failed for {inPath}")
  if code != 0:
    nvRaise(&"FATAL: gpg decrypt failed (exit {code})\n{status}",
            gpgFailureCode(status))
  if verifySig and not gpgStatusHas(status, "GOODSIG"):
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
