## Per-file data keys, and the payload encryption that uses them (format v6).
##
## Until v6 each blob was encrypted straight to the recipient. Both backends do
## envelope encryption internally -- GPG draws a session key per file, age a
## file key -- but that wrapping lives *inside* the blob, so the recipient is
## baked into every payload and changing or adding one rewrites the whole vault.
## For a vault of a few hundred entries that is a full re-encrypt to let a
## second machine read, and a diff nobody can review.
##
## v6 hoists the key out of the payload. Each blob is encrypted under its own
## random data key; the data keys live together in one small file encrypted to
## the recipients. Adding a machine or rotating a recipient key then rewrites
## that one file and leaves every payload alone.
##
## What that gives, precisely: rotation of the *wrapping*. A data key that has
## already leaked stays useful to whoever holds it, because the old ciphertext
## is unchanged -- recovering from that needs the payload re-encrypted, which is
## what `rotate --rekey` is for. The distinction between cheap rewrapping and
## real re-encryption is the subject of Everspaugh et al., CRYPTO 2017
## (doi:10.1007/978-3-319-63697-9_4); updatable encryption exists to narrow the
## gap (Lehmann and Tackmann, EUROCRYPT 2018,
## doi:10.1007/978-3-319-78372-7_22). Conflating the two is how a tool claims a
## compromise was handled when it was not.
##
## Per backend the "data key" is whatever opens a payload non-interactively:
##
## | Backend | Data key | Payload |
## | --- | --- | --- |
## | gpg | 256-bit passphrase, hex | `gpg --symmetric` |
## | age | x25519 identity | `age -r <recipient>` |
##
## Both are ordinary documented modes of the backend already in use, so v6 adds
## no new dependency and no hand-rolled primitive.

import std/[os, osproc, streams, strutils, strformat, sysrand, tables,
            algorithm, sets, re]
import ./gpg
from ./age import ageKeygenBinary, ageRecipientForIdentity, ageBinary
import ./crypto
from ./fsat import runWithInput

const
  KeysFileStem* = "keys"
  DekBytes = 32

type DekTable* = Table[string, string]   ## entry id -> data key

# --- recipient groups -------------------------------------------------------
#
# One key file per distinct recipient set rather than one for the whole vault,
# so a machine holding only some of the keys decrypts only the entries meant
# for it. Without this, splitting paths between machines would be decoration:
# every machine that can read the single key file can read every payload.
#
# The group is named by a digest of its recipient set, not by a label, so two
# rules naming the same recipients share one file and renaming a rule does not
# orphan a key file.

proc normalizedRecipients*(recips: seq[string]): seq[string] =
  ## Sorted and deduplicated, so the name of a group depends on the set and not
  ## on how it was written.
  var seen = initHashSet[string]()
  for r in recips:
    let s = r.strip()
    if s.len > 0 and s notin seen:
      seen.incl(s)
      result.add(s)
  result.sort()

proc groupId*(recips: seq[string]): string =
  let norm = normalizedRecipients(recips)
  if norm.len == 0:
    return "default"
  sha256sumBytes(norm.join("\n"))[0 ..< 16]

proc globToRe(pat: string): string =
  ## Glob, not PCRE. Only `*` and `**` are special.
  result = "^"
  var i = 0
  while i < pat.len:
    if i + 1 < pat.len and pat[i] == '*' and pat[i + 1] == '*':
      if i + 2 < pat.len and pat[i + 2] == '/':
        result.add("(.*/)?")
        i += 3
      else:
        result.add(".*")
        i += 2
    elif pat[i] == '*':
      result.add("[^/]*")
      inc i
    elif pat[i] in {'.', '+', '?', '(', ')', '|', '[', ']', '{', '}',
                    '^', '$', '\\'}:
      result.add('\\')
      result.add(pat[i])
      inc i
    else:
      result.add(pat[i])
      inc i
  result.add("$")

proc matchesGlob(pattern, path: string): bool =
  ## `**` spans separators, `*` does not, and a pattern ending in `/` or `/**`
  ## matches everything beneath it. Deliberately small: a rule that is hard to
  ## predict is a rule that silently sends a secret to the wrong machine.
  var pat = pattern.strip()
  if pat.len == 0:
    return false
  if pat.endsWith("/"):
    pat.add("**")
  return path.match(re(globToRe(pat)))

proc recipientsFor*(cfg: GpgConfig, path: string): seq[string] =
  ## Recipients for one entry: the first matching `wrap` rule wins, and the
  ## configured recipient is the fallback. Order in the file is the precedence,
  ## so the specific rules go above the general one.
  for rule in cfg.wraps:
    let idx = rule.rfind(':')
    if idx <= 0:
      continue
    let pat = rule[0 ..< idx].strip()
    let recips = rule[idx + 1 .. ^1].split(',')
    var hit = matchesGlob(pat, path)
    # Documented `~/…` rules must still match a `root = repo` stored path.
    if not hit and cfg.root.len > 0 and pat.startsWith("~/"):
      hit = matchesGlob(pat[2 .. ^1], path)
    if not hit and cfg.root.len == 0 and path.startsWith("~/") and
       not pat.startsWith("~/"):
      hit = matchesGlob(pat, path[2 .. ^1])
    if hit:
      return normalizedRecipients(recips)
  return normalizedRecipients(@[cfg.recipient])

proc groupKeysPath*(repo: string, cfg: GpgConfig, gid: string): string =
  repo / ".vault" / (KeysFileStem & "." & gid & cfg.blobExt)

proc isKeyFileName(name: string): bool =
  (name.startsWith(KeysFileStem & ".") and
   (name.endsWith(".gpg") or name.endsWith(".age"))) or
  name == KeysFileStem & ".gpg" or name == KeysFileStem & ".age"

proc keyFiles*(repo: string, cfg: GpgConfig): seq[string] =
  ## Every data-key file present, grouped or legacy flat, either backend.
  let dir = repo / ".vault"
  if not dirExists(dir):
    return
  for kind, path in walkDir(dir):
    let name = path.extractFilename
    let keyNode = isKeyFileName(name)
    if kind == pcLinkToFile and keyNode:
      nvRaise(&"FATAL: refusing symlinked key file: {path}")
    if not keyNode:
      continue
    if kind != pcFile:
      nvRaise(&"FATAL: refusing non-regular key file: {path}")
    assertVaultRegularFile(path)
    if name.startsWith(KeysFileStem & ".") and
       (name.endsWith(".gpg") or name.endsWith(".age")):
      result.add(path)


proc keysPath*(repo: string, cfg: GpgConfig): string =
  repo / ".vault" / (KeysFileStem & cfg.blobExt)

proc findKeysFile*(repo: string, cfg: GpgConfig): string =
  ## Read whichever backend wrote it, so a vault mid-migration still opens.
  let mine = keysPath(repo, cfg)
  if symlinkExists(mine):
    nvRaise(&"FATAL: refusing symlinked key file: {mine}")
  if fileExists(mine):
    assertVaultRegularFile(mine)
    return mine
  let other = repo / ".vault" / (KeysFileStem &
              (if cfg.usesAge: ".gpg" else: ".age"))
  if symlinkExists(other):
    nvRaise(&"FATAL: refusing symlinked key file: {other}")
  if fileExists(other):
    assertVaultRegularFile(other)
    return other
  return ""

proc newDek*(cfg: GpgConfig): string =
  ## Fresh data key for one entry.
  if cfg.usesAge:
    # An age identity is the only thing age will decrypt with unattended, so
    # that is what a data key is for this backend.
    let p = startProcess(ageKeygenBinary(), args = @[],
                         options = {poUsePath, poStdErrToStdOut})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: age-keygen failed (exit {code}):\n{output}")
    for line in output.splitLines:
      let s = line.strip()
      if s.startsWith("AGE-SECRET-KEY-"):
        return s
    nvRaise("FATAL: age-keygen produced no identity")
  else:
    var buf: array[DekBytes, byte]
    doAssert urandom(buf)
    for b in buf:
      result.add(b.toHex(2).toLowerAscii())

proc loadDeksFromKeys*(repo: string, cfg: GpgConfig): DekTable =
  ## Data keys from keys.* files only.
  let dir = repo / ".vault"
  if not dirExists(dir):
    return
  var candidates: seq[string] = @[]
  for kind, path in walkDir(dir):
    let name = path.extractFilename
    let keyNode = isKeyFileName(name)
    if kind == pcLinkToFile and keyNode:
      nvRaise(&"FATAL: refusing symlinked key file: {path}")
    if not keyNode:
      continue
    if kind != pcFile:
      nvRaise(&"FATAL: refusing non-regular key file: {path}")
    assertVaultRegularFile(path)
    candidates.add(path)
  for path in candidates:
    var plain = ""
    try:
      plain = decryptBytesToString(cfg, readVaultRegularFile(path), path, false)
    except CatchableError:
      continue
    for line in plain.splitLines:
      let s = line.strip()
      if s.len == 0 or s.startsWith("#"):
        continue
      let parts = s.split('\t')
      if parts.len >= 2:
        result[parts[0]] = parts[1]

proc loadDeks*(repo: string, cfg: GpgConfig): DekTable =
  ## Merge every data-key this machine can actually open.
  ##
  ## Per-entry records under `.vault/e/` are the mergeable source. Grouped
  ## `keys.*` files still fill ids whose record carries no data key, or that
  ## have no record yet (a v6 vault mid-migration). A file that will not
  ## decrypt is not an error: it belongs to a group this machine is not in.
  let dir = repo / ".vault"
  if not dirExists(dir):
    return
  let requireSig = cfg.effectiveSigner != "none"
  template sigFailure(msg: string): bool =
    requireSig and ("signature verification failed" in msg or
                    "missing signature" in msg or
                    "signature required" in msg)
  proc noSecretKey(msg: string): bool =
    if cfg.usesAge:
      let low = msg.toLowerAscii()
      ("no identity matched" in low) or ("no identities matched" in low)
    else:
      gpgNoSecretKey(msg)
  let edir = dir / "e"
  if dirExists(edir):
    let work = privateWorkDir()
    defer:
      discardPrivate(work)
    var snapN = 0
    for kind, path in walkDir(edir):
      let name = path.extractFilename
      let recordNode = name.endsWith(".gpg") or name.endsWith(".age") or
                       name.endsWith(".sig")
      if kind == pcLinkToFile and recordNode:
        nvRaise(&"FATAL: refusing symlinked record file: {path}")
      if not recordNode:
        continue
      if kind != pcFile:
        nvRaise(&"FATAL: refusing non-regular record file: {path}")
      assertVaultRegularFile(path)
      if name.endsWith(".sig"):
        continue
      let ext = if name.endsWith(".age"): ".age" else: ".gpg"
      let snap = work / ("record-" & $snapN & ext)
      inc snapN
      writeFile(snap, readVaultRegularFile(path))
      let sig = path & ".sig"
      if fileExists(sig):
        writeFile(snap & ".sig", readVaultRegularFile(sig))
      var plain = ""
      try:
        plain = verifyAndDecryptToString(cfg, snap, verifySig = requireSig,
                                         checkPresent = true)
      except CatchableError as err:
        var msg = err.msg
        if snap in msg:
          msg = msg.replace(snap, path)
        if (snap & ".sig") in msg:
          msg = msg.replace(snap & ".sig", path & ".sig")
        if sigFailure(msg):
          nvRaise(msg)
        if noSecretKey(msg):
          continue
        nvRaise(msg)
      for line in plain.splitLines:
        let s = line.strip()
        if s.len == 0 or s.startsWith("#"):
          continue
        let parts = s.split('\t')
        if parts.len >= 6 and parts[5].len > 0:
          result[parts[0]] = parts[5]
  for id, key in loadDeksFromKeys(repo, cfg):
    if id notin result:
      # A key file is not signed, so a data key in a record wins. The key
      # file fills any id the records left without one: an id with no record
      # (a v6 vault mid-migration) and a record whose data-key field is empty.
      result[id] = key

proc saveDeksGrouped*(repo: string, cfg: GpgConfig, deks: DekTable,
                      groupOf: Table[string, string],
                      recipsOf: Table[string, seq[string]]) =
  ## One key file per recipient group, each encrypted to that group only.
  ##
  ## Written atomically and flushed, because a key file is as load bearing as
  ## the manifest: losing it loses every payload it names. Groups that no
  ## longer hold any entry have their file removed rather than left behind
  ## still able to open blobs.
  let dir = repo / ".vault"
  var byGroup: Table[string, seq[string]]
  for id, dek in deks:
    let gid = groupOf.getOrDefault(id, "default")
    byGroup.mgetOrPut(gid, @[]).add(&"{id}\t{dek}")

  for gid, lines in byGroup:
    let path = groupKeysPath(repo, cfg, gid)
    let work = privateWorkDir()
    let plainPath = work / "keys.plain"
    let cipherPath = work / ("keys" & cfg.blobExt)
    var content = "# vault-keys-v6\n"
    for l in lines:
      content.add(l & "\n")
    writeFile(plainPath, content)
    setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
    try:
      encryptFileTo(cfg, recipsOf.getOrDefault(gid, @[cfg.recipient]),
                    plainPath, cipherPath, sign = false)
      publishFileNofollow(cipherPath, path)
    finally:
      discardPrivate(work)

  # Drop key files for groups that no longer have entries.
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if not name.startsWith(KeysFileStem & "."):
      continue
    let stem = name.rsplit('.', maxsplit = 1)[0]      # keys.<gid>
    let gid = if '.' in stem: stem.rsplit('.', maxsplit = 1)[1] else: ""
    if gid.len == 0:
      # The pre-groups flat file. Its keys have just been written into the
      # group files, so keeping it would leave a second copy of every key
      # readable by the default recipient alone.
      if byGroup.len > 0:
        removeFile(path)
    elif gid notin byGroup:
      # A wrap-subset machine cannot see every group. Leave a file
      # this identity cannot decrypt.
      try:
        discard decryptToString(cfg, path, false)
        removeFile(path)
      except CatchableError:
        discard

proc encryptWithDek*(cfg: GpgConfig, dek, inPath, outPath: string): string =
  ## Encrypt a payload under its data key. No recipient is involved, which is
  ## the whole point. Return the digest of the ciphertext this process wrote
  ## before publishing it, so callers can keep metadata bound to those bytes.
  createDir(outPath.parentDir)
  let work = privateWorkDir()
  let tmp = work / ("cipher" & cfg.blobExt)
  try:
    if cfg.usesAge:
      let recip = ageRecipientForIdentity(dek)
      let p = startProcess(ageBinary(),
        args = @["-r", recip, "-o", tmp, "--", inPath],
        options = {poUsePath, poStdErrToStdOut})
      let output = p.outputStream.readAll()
      let code = p.waitForExit()
      p.close()
      if code != 0:
        if fileExists(tmp): removeFile(tmp)
        nvRaise(&"FATAL: age encrypt failed (exit {code}):\n{output}")
    else:
      # Passphrase on a pipe, never argv: /proc/<pid>/cmdline is world readable.
      let p = startProcess("gpg",
        args = @["--batch", "--yes", "--quiet", "--symmetric",
                 "--cipher-algo", "AES256", "--passphrase-fd", "0",
                 "--pinentry-mode", "loopback",
                 "--set-filename", "", "-o", tmp, "--", inPath],
        options = {poUsePath, poStdErrToStdOut})
      p.inputStream.write(dek & "\n")
      p.inputStream.close()
      let output = p.outputStream.readAll()
      let code = p.waitForExit()
      p.close()
      if code != 0:
        if fileExists(tmp): removeFile(tmp)
        nvRaise(&"FATAL: gpg symmetric encrypt failed (exit {code}):\n{output}")
    result = sha256sum(tmp)
    syncPath(tmp)
    publishFileNofollow(tmp, outPath)
  finally:
    discardPrivate(work)

proc decryptWithDekBytesToString*(cfg: GpgConfig, dek, cipher: string): string =
  ## Plaintext in memory from ciphertext bytes already read by the caller.
  if cfg.usesAge:
    let work = privateWorkDir()
    let identFile = work / "identity"
    writeFile(identFile, dek & "\n")
    setFilePermissions(identFile, {fpUserRead, fpUserWrite})
    defer:
      discardPrivate(work)
    let p = startProcess(ageBinary(),
      args = @["-d", "-i", identFile, "--", "-"],
      options = {poUsePath})
    let io = runWithInput(p, cipher)
    if io.writeErr != 0:
      var msg = "FATAL: age decrypt failed while writing ciphertext: " &
                osErrorMsg(OSErrorCode(io.writeErr))
      let detail = io.err.strip()
      if detail.len > 0:
        msg.add("\n" & detail)
      nvRaise(msg)
    if io.code != 0:
      nvRaise(&"FATAL: age decrypt failed (exit {io.code}):\n{io.err}")
    result = io.outp
  else:
    let work = privateWorkDir()
    defer:
      discardPrivate(work)
    let passFile = work / "passphrase"
    writeFile(passFile, dek & "\n")
    setFilePermissions(passFile, {fpUserRead, fpUserWrite})
    let p = startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--decrypt",
               "--status-fd", "2",
               "--passphrase-file", passFile, "--pinentry-mode", "loopback",
               "--", "-"],
      options = {poUsePath})
    let io = runWithInput(p, cipher)
    if io.writeErr != 0 and io.code == 0:
      nvRaise("FATAL: gpg symmetric decrypt failed while writing ciphertext: " &
              osErrorMsg(OSErrorCode(io.writeErr)))
    if io.code != 0:
      nvRaise(&"FATAL: gpg symmetric decrypt failed (exit {io.code}):\n{io.err}")
    if not gpgStatusHas(io.err, "NEED_PASSPHRASE_SYM") or
       not gpgStatusHas(io.err, "DECRYPTION_OKAY"):
      nvRaise("FATAL: payload decrypt did not use the entry's symmetric data " &
              "key.\n" & io.err)
    result = io.outp

proc decryptWithDekToString*(cfg: GpgConfig, dek, inPath: string): string =
  ## Plaintext in memory. The data key for age still needs an identity file;
  ## the plaintext itself is not written.
  decryptWithDekBytesToString(cfg, dek, readFile(inPath))
