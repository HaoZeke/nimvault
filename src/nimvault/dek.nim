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

proc matchesGlob(pattern, path: string): bool =
  ## `**` spans separators, `*` does not, and a pattern ending in `/` or `/**`
  ## matches everything beneath it. Deliberately small: a rule that is hard to
  ## predict is a rule that silently sends a secret to the wrong machine.
  var pat = pattern.strip()
  if pat.len == 0:
    return false
  if pat.endsWith("/"):
    pat.add("**")
  # Anchored at both ends: an unanchored pattern matches a prefix, so `~/x/*`
  # would quietly cover `~/x/deep/one` and send it to the wrong machine.
  let rx = "^" & pat.replace(".", "\\.")
                    .replace("**", "\u0001")
                    .replace("*", "[^/]*")
                    .replace("\u0001", ".*") & "$"
  return path.match(re(rx))

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
    if matchesGlob(pat, path):
      return normalizedRecipients(recips)
  return normalizedRecipients(@[cfg.recipient])

proc groupKeysPath*(repo: string, cfg: GpgConfig, gid: string): string =
  repo / ".vault" / (KeysFileStem & "." & gid & cfg.blobExt)

proc keyFiles*(repo: string, cfg: GpgConfig): seq[string] =
  ## Every data-key file present, grouped or legacy flat, either backend.
  let dir = repo / ".vault"
  if not dirExists(dir):
    return
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.startsWith(KeysFileStem & ".") and
       (name.endsWith(".gpg") or name.endsWith(".age")):
      result.add(path)


proc keysPath*(repo: string, cfg: GpgConfig): string =
  repo / ".vault" / (KeysFileStem & cfg.blobExt)

proc findKeysFile*(repo: string, cfg: GpgConfig): string =
  ## Read whichever backend wrote it, so a vault mid-migration still opens.
  let mine = keysPath(repo, cfg)
  if fileExists(mine):
    return mine
  let other = repo / ".vault" / (KeysFileStem &
              (if cfg.usesAge: ".gpg" else: ".age"))
  if fileExists(other):
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

proc loadDeks*(repo: string, cfg: GpgConfig): DekTable =
  ## Merge every data-key file this machine can actually open.
  ##
  ## A file that will not decrypt is not an error: it belongs to a group whose
  ## recipients do not include this machine, which is the feature working. The
  ## caller finds out per entry, when it looks for a key and there is none.
  let dir = repo / ".vault"
  if not dirExists(dir):
    return
  var candidates: seq[string] = @[]
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.startsWith(KeysFileStem & ".") or
       name == KeysFileStem & ".gpg" or name == KeysFileStem & ".age":
      candidates.add(path)
  for path in candidates:
    var plain = ""
    try:
      plain = decryptToString(cfg, path, false)
    except CatchableError:
      continue        # not ours to read
    for line in plain.splitLines:
      let s = line.strip()
      if s.len == 0 or s.startsWith("#"):
        continue
      let parts = s.split('\t')
      if parts.len >= 2:
        result[parts[0]] = parts[1]

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
    let plainPath = dir / (".keys." & gid & ".plain")
    var content = "# vault-keys-v6\n"
    for l in lines:
      content.add(l & "\n")
    writeFile(plainPath, content)
    setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
    let tmp = path & ".tmp"
    encryptFileTo(cfg, recipsOf.getOrDefault(gid, @[cfg.recipient]),
                  plainPath, tmp, sign = false)
    removeFile(plainPath)
    syncPath(tmp)
    moveFile(tmp, path)
    syncParentDir(path)

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
      removeFile(path)

proc encryptWithDek*(cfg: GpgConfig, dek, inPath, outPath: string) =
  ## Encrypt a payload under its data key. No recipient is involved, which is
  ## the whole point.
  if cfg.usesAge:
    let recip = ageRecipientForIdentity(dek)
    let p = startProcess(ageBinary(),
      args = @["-r", recip, "-o", outPath, inPath],
      options = {poUsePath, poStdErrToStdOut})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: age encrypt failed (exit {code}):\n{output}")
  else:
    # Passphrase on a pipe, never argv: /proc/<pid>/cmdline is world readable.
    let p = startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--symmetric",
               "--cipher-algo", "AES256", "--passphrase-fd", "0",
               "--pinentry-mode", "loopback",
               "--set-filename", "", "-o", outPath, inPath],
      options = {poUsePath, poStdErrToStdOut})
    p.inputStream.write(dek & "\n")
    p.inputStream.close()
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: gpg symmetric encrypt failed (exit {code}):\n{output}")

proc decryptWithDek*(cfg: GpgConfig, dek, inPath, outPath: string) =
  ## Decrypt a v6 payload with its data key.
  if cfg.usesAge:
    let identFile = getTempDir() / &"nimvault-dek-{getCurrentProcessId()}"
    writeFile(identFile, dek & "\n")
    setFilePermissions(identFile, {fpUserRead, fpUserWrite})
    defer: removeFile(identFile)
    let p = startProcess(ageBinary(),
      args = @["-d", "-i", identFile, "-o", outPath, inPath],
      options = {poUsePath, poStdErrToStdOut})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: age decrypt failed (exit {code}):\n{output}")
  else:
    let p = startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--decrypt",
               "--passphrase-fd", "0", "--pinentry-mode", "loopback",
               "-o", outPath, inPath],
      options = {poUsePath, poStdErrToStdOut})
    p.inputStream.write(dek & "\n")
    p.inputStream.close()
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: gpg symmetric decrypt failed (exit {code}):\n{output}")
