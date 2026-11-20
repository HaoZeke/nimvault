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
            algorithm, sets]
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
  ## `**` spans separators, `*` does not, and a pattern ending in `/` matches
  ## everything beneath it. `?` and the other punctuation are literal, and the
  ## match is anchored at both ends. Deliberately small: a rule that is hard
  ## to predict is a rule that silently sends a secret to the wrong machine.
  ##
  ## Same paths as the old glob-to-PCRE translation (`**/` was `(.*/)?`, a
  ## bare `**` was `.*`, a single `*` was `[^/]*`), without loading libpcre.
  var pat = pattern.strip()
  if pat.len == 0:
    return false
  if pat.endsWith("/"):
    pat.add("**")

  proc rec(pi, ti: int): bool =
    if pi == pat.len:
      # `$` is the end, or the position just before one trailing newline.
      if ti == path.len:
        return true
      return ti == path.len - 1 and path[ti] == '\n'
    if pi + 1 < pat.len and pat[pi] == '*' and pat[pi + 1] == '*':
      if pi + 2 < pat.len and pat[pi + 2] == '/':
        # Optional run of segments on this line: `dir/name` and a bare `name`.
        # `.` does not cross a newline, so a `/` past one does not count.
        let rest = pi + 3
        var limit = ti
        while limit < path.len and path[limit] != '\n':
          inc limit
        var k = limit - 1
        while k >= ti:
          if path[k] == '/':
            if rec(rest, k + 1):
              return true
          dec k
        return rec(rest, ti)
      # `.*` stays on this line.
      let rest = pi + 2
      var limit = ti
      while limit < path.len and path[limit] != '\n':
        inc limit
      for n in countdown(limit, ti):
        if rec(rest, n):
          return true
      return false
    elif pat[pi] == '*':
      let rest = pi + 1
      var endPos = ti
      while endPos < path.len and path[endPos] != '/':
        inc endPos
      for n in countdown(endPos, ti):
        if rec(rest, n):
          return true
      return false
    elif ti < path.len and path[ti] == pat[pi]:
      rec(pi + 1, ti + 1)
    else:
      false

  rec(0, 0)

when defined(nimvaultTest):
  proc matchGlob*(pattern, path: string): bool =
    ## Test hook for the wrap-rule glob.
    matchesGlob(pattern, path)

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

proc loadDeksFromKeys*(repo: string, cfg: GpgConfig): DekTable =
  ## Data keys from keys.* files only.
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
  let edir = dir / "e"
  if dirExists(edir):
    for kind, path in walkDir(edir):
      if kind != pcFile:
        continue
      let name = path.extractFilename
      if not (name.endsWith(".gpg") or name.endsWith(".age")):
        continue
      var plain = ""
      try:
        plain = decryptToString(cfg, path, false)
      except CatchableError:
        continue
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
    var content = "# vault-keys-v6\n"
    for l in lines:
      content.add(l & "\n")
    writeFile(plainPath, content)
    setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
    let tmp = path & ".tmp"
    try:
      encryptFileTo(cfg, recipsOf.getOrDefault(gid, @[cfg.recipient]),
                    plainPath, tmp, sign = false)
    finally:
      discardPrivate(work)
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
      # A wrap-subset machine cannot see every group. Leave a file
      # this identity cannot decrypt.
      try:
        discard decryptToString(cfg, path, false)
        removeFile(path)
      except CatchableError:
        discard

proc encryptWithDek*(cfg: GpgConfig, dek, inPath, outPath: string) =
  ## Encrypt a payload under its data key. No recipient is involved, which is
  ## the whole point. Write beside the live blob and rename so a crash
  ## does not truncate the last sealed copy.
  createDir(outPath.parentDir)
  let tmp = outPath & ".tmp"
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
  syncPath(tmp)
  moveFile(tmp, outPath)
  syncParentDir(outPath)

proc decryptWithDekStream*(cfg: GpgConfig, dek, inPath: string,
                           work: var string): Process =
  ## Spawn a decryption of a v6 payload that writes the plaintext to stdout.
  ## For age the data key is an identity file in `work`, a private directory
  ## the caller discards once the process has exited.
  work = ""
  if cfg.usesAge:
    work = privateWorkDir()
    let identFile = work / "identity"
    writeFile(identFile, dek & "\n")
    setFilePermissions(identFile, {fpUserRead, fpUserWrite})
    result = startProcess(ageBinary(),
      args = @["-d", "-i", identFile, "--", inPath],
      options = {poUsePath})
  else:
    result = startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--decrypt",
               "--passphrase-fd", "0", "--pinentry-mode", "loopback",
               "--", inPath],
      options = {poUsePath})
    # A gpg that exits before reading the key fails on its own; the caller
    # still has to reap it, so a closed pipe is not raised from here.
    try:
      result.inputStream.write(dek & "\n")
    except IOError, OSError:
      discard
    try:
      result.inputStream.close()
    except IOError, OSError:
      discard

proc decryptWithDekToString*(cfg: GpgConfig, dek, inPath: string): string =
  ## Plaintext in memory. The data key for age still needs an identity file;
  ## the plaintext itself is not written.
  if cfg.usesAge:
    let work = privateWorkDir()
    let identFile = work / "identity"
    writeFile(identFile, dek & "\n")
    setFilePermissions(identFile, {fpUserRead, fpUserWrite})
    defer:
      discardPrivate(work)
    let p = startProcess(ageBinary(),
      args = @["-d", "-i", identFile, "--", inPath],
      options = {poUsePath})
    result = p.outputStream.readAll()
    let err = p.errorStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: age decrypt failed (exit {code}):\n{err}")
  else:
    let p = startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--decrypt",
               "--passphrase-fd", "0", "--pinentry-mode", "loopback",
               "--", inPath],
      options = {poUsePath})
    p.inputStream.write(dek & "\n")
    p.inputStream.close()
    result = p.outputStream.readAll()
    let err = p.errorStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: gpg symmetric decrypt failed (exit {code}):\n{err}")
