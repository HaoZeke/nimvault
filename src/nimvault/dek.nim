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

import std/[os, osproc, streams, strutils, strformat, sysrand, tables]
import ./gpg
from ./age import ageKeygenBinary, ageRecipientForIdentity, ageBinary
import ./crypto

const
  KeysFileStem* = "keys"
  DekBytes = 32

type DekTable* = Table[string, string]   ## entry id -> data key

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
  ## Decrypt the data-key file. An absent file is an empty table, which is what
  ## a v5 vault looks like and is not an error.
  let path = findKeysFile(repo, cfg)
  if path.len == 0:
    return
  let plain = decryptToString(cfg, path, false)
  for line in plain.splitLines:
    let s = line.strip()
    if s.len == 0 or s.startsWith("#"):
      continue
    let parts = s.split('\t')
    if parts.len >= 2:
      result[parts[0]] = parts[1]

proc saveDeks*(repo: string, cfg: GpgConfig, deks: DekTable) =
  ## Encrypt the data-key file to the recipients, atomically and durably: it is
  ## as load bearing as the manifest, and losing it loses every payload.
  let path = keysPath(repo, cfg)
  let plainPath = repo / ".vault" / (".keys.plain")
  var content = "# vault-keys-v6\n"
  for id, dek in deks:
    content.add(&"{id}\t{dek}\n")
  writeFile(plainPath, content)
  setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
  let tmp = path & ".tmp"
  encryptFile(cfg, plainPath, tmp)
  removeFile(plainPath)
  syncPath(tmp)
  moveFile(tmp, path)
  syncParentDir(path)

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
