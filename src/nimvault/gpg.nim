## GPG encryption/decryption and recipient resolution.

import std/[os, osproc, strutils, strformat, streams, sequtils]
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
    wraps*: seq[string]     ## `<glob>:<recipient>[,...]` rules, in file order

proc nvRaise*(msg: string) =
  ## Library-safe failure (no process exit). CLI catches and quits.
  raise newException(NimvaultError, msg)

var nvQuiet* {.threadvar.}: bool  ## When true, suppress banners/echo (C ABI / MCP in-process)

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

proc checkGpgConfig(cfg: GpgConfig)

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
  checkGpgConfig(result)

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

proc vaultSignerSpecs*(cfg: GpgConfig): seq[string] =
  ## Key specifiers allowed to sign this vault: the recipient and every
  ## recipient a wrap rule names. A machine that writes records is one the
  ## config already lists, since it has to be able to read them.
  proc keep(acc: var seq[string], s: string) =
    let t = s.strip()
    if t.len > 0 and t notin acc:
      acc.add(t)
  keep(result, cfg.recipient)
  for rule in cfg.wraps:
    let idx = rule.rfind(':')
    if idx <= 0:
      continue
    for r in rule[idx + 1 .. ^1].split(','):
      keep(result, r)

proc normalizeHexSpec(s: string): string =
  var t = s.strip()
  if t.len >= 2 and (t[0] == '0') and (t[1] in {'x', 'X'}):
    t = t[2 .. ^1]
  t.toUpperAscii()

proc isHexSpec(s: string): bool =
  let t = normalizeHexSpec(s)
  if t.len < 8:
    return false
  for ch in t:
    if ch notin {'0'..'9', 'A'..'F'}:
      return false
  true

proc parseEmailSpec(s: string): string =
  var t = s.strip()
  if t.startsWith("<") and t.endsWith(">") and t.len > 2:
    t = t[1 ..< t.len - 1].strip()
  if t.len == 0 or '@' notin t:
    return ""
  if ' ' in t or '\t' in t:
    return ""
  t.toLowerAscii()

proc uidEmail(uid: string): string =
  let lo = uid.rfind('<')
  if lo >= 0:
    let hi = uid.find('>', lo + 1)
    if hi > lo + 1:
      return uid[lo + 1 ..< hi].strip().toLowerAscii()
  let t = uid.strip()
  if '@' in t and ' ' notin t and '\t' notin t:
    return t.toLowerAscii()
  ""

type ListedKey = tuple[keyId, fpr: string, emails: seq[string]]

proc parseListedKeys(listing: string): seq[ListedKey] =
  var cur = -1
  var needFpr = false
  for line in listing.splitLines:
    let fields = line.split(':')
    if fields.len < 10:
      continue
    case fields[0]
    of "pub", "sec":
      result.add((fields[4].toUpperAscii(), "", @[]))
      cur = result.high
      needFpr = true
    of "fpr":
      if cur >= 0 and needFpr and fields[9].len > 0:
        result[cur].fpr = fields[9].toUpperAscii()
        needFpr = false
    of "uid":
      if cur >= 0 and fields[9].len > 0:
        let email = uidEmail(fields[9])
        if email.len > 0 and email notin result[cur].emails:
          result[cur].emails.add(email)
    else:
      discard

proc signerFingerprints*(specs: seq[string], secretOnly = false): seq[string] =
  ## Primary-key fingerprints, upper case, of every key in the keyring that one
  ## of `specs` names. Email specs are exact (`<addr>`), and key IDs or
  ## fingerprints are exact hex matches.
  for raw in specs:
    let s = raw.strip()
    if s.len == 0 or s[0] == '-' or '\n' in s or '\r' in s or '\0' in s:
      continue
    let email = parseEmailSpec(s)
    let hex = if email.len == 0 and isHexSpec(s): normalizeHexSpec(s) else: ""
    if email.len == 0 and hex.len == 0:
      continue
    let query = if email.len > 0: "<" & email & ">" else: hex
    var args = @["--batch", "--no-options", "--with-colons", "--fingerprint",
                 (if secretOnly: "--list-secret-keys" else: "--list-keys"), "--",
                 query]
    let p = startProcess("gpg", args = args, options = {poUsePath, poStdErrToStdOut})
    let listing = p.outputStream.readAll()
    discard p.waitForExit()
    p.close()
    for key in parseListedKeys(listing):
      let keyId = normalizeHexSpec(key.keyId)
      let fpr = normalizeHexSpec(if key.fpr.len > 0: key.fpr else: key.keyId)
      let ok =
        if email.len > 0:
          key.emails.anyIt(it == email)
        else:
          fpr == hex or keyId == hex or
            (hex.len <= keyId.len and hex.len in [8, 16] and keyId.endsWith(hex))
      if ok and fpr.len > 0 and fpr notin result:
        result.add(fpr)

proc vaultSigners*(cfg: GpgConfig): seq[string] =
  signerFingerprints(vaultSignerSpecs(cfg))

proc exactKeySpec(s: string): bool =
  ## An email address, key ID or fingerprint. gpg matches any other string
  ## anywhere in a user ID, so `Alice` also names `Malice <malice@...>`.
  parseEmailSpec(s).len > 0 or isHexSpec(s)

const AgeGpgSigner* = "signer = gpg does not sign an age vault: gpg signs " &
  "only what it encrypts.\n  Use signer = ssh with sign_key, allowed_signers " &
  "and signer_identity."

proc checkGpgConfig(cfg: GpgConfig) =
  ## Refuse a config whose signer would sign and verify nothing without
  ## saying so.
  if cfg.backend notin ["gpg", "age"]:
    nvRaise(&"FATAL: unknown backend `{cfg.backend}`; use gpg or age")
  if cfg.signer notin ["gpg", "ssh", "none"]:
    nvRaise(&"FATAL: unknown signer `{cfg.signer}`; use gpg, ssh or none")
  if cfg.backend == "age" and cfg.signer == "gpg":
    nvRaise("FATAL: " & AgeGpgSigner)
  if cfg.backend == "gpg":
    for spec in vaultSignerSpecs(cfg):
      if not exactKeySpec(spec):
        nvRaise(&"FATAL: recipient `{spec}` does not name one key.\n" &
                "  Use an email address, a key ID or a fingerprint. gpg " &
                "matches any other string anywhere in a user ID.")

proc signingKey*(cfg: GpgConfig): string =
  ## Pick an allowed signer key this machine can use, in config order.
  let specs = vaultSignerSpecs(cfg)
  for spec in specs:
    let mine = signerFingerprints(@[spec], secretOnly = true)
    if mine.len > 0:
      return mine[0]
  nvRaise("FATAL: no allowed secret key is available for signing.\n" &
          "  Signers are the recipient and the wrap-rule recipients in .vault/config.")

proc validSigners*(status: string): seq[string] =
  ## Primary-key fingerprint of each VALIDSIG line, upper case. gpg omits the
  ## primary field for a signature by a primary key on some versions; the
  ## signing-key fingerprint is then the primary one.
  const prefix = "[GNUPG:] VALIDSIG "
  for line in status.splitLines:
    let s = line.strip()
    if not s.startsWith(prefix):
      continue
    let fields = s[prefix.len .. ^1].splitWhitespace()
    if fields.len >= 10:
      result.add(fields[9].toUpperAscii())
    elif fields.len >= 1:
      result.add(fields[0].toUpperAscii())

proc gpgSignerProblem*(status, path: string, allowed: seq[string]): string =
  ## Empty when every signature gpg validated was made by a key in
  ## `allowed`. GOODSIG alone only says that some key in the keyring signed.
  ## The message keeps "signature verification failed" so callers that sort
  ## fatal from skippable failures treat it as fatal.
  let got = validSigners(status)
  if got.len == 0:
    return &"FATAL: signature verification failed for {path}: no VALIDSIG status"
  for fpr in got:
    if fpr notin allowed:
      return &"FATAL: signature verification failed for {path}: signed by " &
             &"{fpr}, which is not a key this vault is configured for.\n" &
             "  Signers are the recipient and the wrap-rule recipients in .vault/config."
  ""

proc gpgEncrypt*(cfg: GpgConfig, inPath, outPath: string) =
  ## Encrypt and sign a file using GPG with the configured recipient.
  if cfg.recipient.len == 0 or cfg.recipient[0] == '-' or
     '\n' in cfg.recipient or '\r' in cfg.recipient or '\0' in cfg.recipient:
    nvRaise("FATAL: invalid recipient")
  let signer = signingKey(cfg)
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--no-options", "--no-encrypt-to",
             "--trust-model", "always",
             "--local-user", signer,
             "--sign", "-e", "--recipient=" & cfg.recipient,
             "--set-filename", "", "-o", outPath, "--", inPath],
    options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  if code != 0:
    nvRaise(&"FATAL: gpg encrypt failed (exit {code}):\n{output}")

proc gpgVerdict*(status, path: string, code: int, verifySig: bool,
                 allowed: seq[string], checkPresent = false): string =
  ## Empty when a decrypt that exited with `code` and wrote `status` is
  ## acceptable; otherwise the message to raise. `checkPresent` is what
  ## `--allow-unsigned` asks for: a missing signature passes, but one that is
  ## there must verify and come from a key in `allowed`.
  let strict = verifySig or checkPresent
  if strict and (gpgStatusHas(status, "BADSIG") or gpgStatusHas(status, "ERRSIG")):
    return &"FATAL: signature verification failed for {path}"
  if code != 0:
    return &"FATAL: gpg decrypt failed (exit {code})\n{status}"
  if verifySig and not gpgStatusHas(status, "GOODSIG"):
    return &"FATAL: missing signature on {path}. Pass --allow-unsigned to accept unsigned vaults."
  if verifySig or (checkPresent and (gpgStatusHas(status, "GOODSIG") or
                                     validSigners(status).len > 0)):
    return gpgSignerProblem(status, path, allowed)
  ""

proc pkdecryptCodes(status: string): seq[int] =
  ## Error code of each `ERROR pkdecrypt_failed` line: the low 16 bits of the
  ## gpg_error_t gpg prints. 17 is no secret key, 18 wrong secret key.
  const prefix = "[GNUPG:] ERROR pkdecrypt_failed "
  for line in status.splitLines:
    let s = line.strip()
    if s.startsWith(prefix):
      try:
        result.add(parseInt(s[prefix.len .. ^1].strip()) and 0xFFFF)
      except ValueError:
        result.add(-1)

proc encToKeyIds(status: string): seq[string] =
  const prefix = "[GNUPG:] ENC_TO "
  for line in status.splitLines:
    let s = line.strip()
    if s.startsWith(prefix):
      let fields = s[prefix.len .. ^1].splitWhitespace()
      if fields.len > 0:
        result.add(fields[0].toUpperAscii())

proc holdsSecretKey(keyId: string): bool =
  ## True when the keyring has the secret part of key or subkey `keyId`, not
  ## only a stub.
  if keyId.len == 0 or not keyId.allIt(it in HexDigits):
    return false
  let p = startProcess("gpg",
    args = @["--batch", "--no-options", "--with-colons", "--list-secret-keys",
             "--", keyId],
    options = {poUsePath, poStdErrToStdOut})
  let listing = p.outputStream.readAll()
  discard p.waitForExit()
  p.close()
  for line in listing.splitLines:
    let fields = line.split(':')
    if fields.len > 14 and fields[0] in ["sec", "ssb"] and
       fields[4].toUpperAscii() == keyId and fields[14] != "#":
      return true

proc gpgNoSecretKey*(status: string): bool =
  ## True when a decrypt failed because the record is not for this machine.
  ## gpg reports NO_SECKEY for a session-key packet that names a key it holds
  ## but cannot open (code 18, wrong secret key), which is what a corrupted or
  ## forged packet looks like. That is skippable only when every failure was
  ## code 17 or the keyring holds none of the keys the record names.
  if not gpgStatusHas(status, "NO_SECKEY"):
    return false
  let codes = pkdecryptCodes(status)
  if codes.len > 0 and codes.allIt(it == 17):
    return true
  not encToKeyIds(status).anyIt(holdsSecretKey(it))

proc gpgDecrypt*(cfg: GpgConfig, inPath, outPath: string, verifySig = false) =
  ## Decrypt a GPG-encrypted file to a target path. With `verifySig` the
  ## signature must come from a key `cfg` names.
  let allowed = if verifySig: vaultSigners(cfg) else: @[]
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
             "-d", "-o", outPath, "--", inPath],
    options = {poUsePath})
  discard p.outputStream.readAll()
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  let problem = gpgVerdict(status, inPath, code, verifySig, allowed)
  if problem.len > 0:
    nvRaise(problem)

proc gpgDecryptToString*(cfg: GpgConfig, inPath: string, verifySig = false,
                         checkPresent = false): string =
  let allowed = if verifySig or checkPresent: vaultSigners(cfg) else: @[]
  let p = startProcess("gpg",
    args = @["--batch", "--yes", "--quiet", "--status-fd", "2", "-d", "--", inPath],
    options = {poUsePath})
  result = p.outputStream.readAll()
  let status = p.errorStream.readAll()
  let code = p.waitForExit()
  p.close()
  let problem = gpgVerdict(status, inPath, code, verifySig, allowed, checkPresent)
  if problem.len > 0:
    nvRaise(problem)

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
