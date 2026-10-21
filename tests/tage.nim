## Round-trip for the age backend with a detached ssh signature.
##
## Skips itself when `age` or `ssh-keygen` is absent rather than failing, so the
## suite still runs on a machine that only has gpg. A skip is announced, since a
## test that quietly does nothing is worse than one that is not there.

import std/[os, osproc, strutils, strformat, tempfiles, tables, streams]
import nimvault/[gpg, manifest, commands, crypto, dek]

proc have(bin: string): bool = findExe(bin).len > 0

if not (have("age") or have("rage")) or not have("ssh-keygen"):
  echo "SKIP: age backend tests (age or ssh-keygen not installed)"
  quit(0)

let ageBin = if have("age"): "age" else: "rage"
let keygenBin = if have("age-keygen"): "age-keygen" else: "rage-keygen"
if not have(keygenBin):
  echo "SKIP: age backend tests (no age-keygen)"
  quit(0)

let work = createTempDir("nimvault_age_", "_test")
discard execCmdEx(&"git init -q {work.quoteShell}")
createDir(work / ".vault")

# age identity and its recipient
let identPath = work / "id.txt"
let (kgOut, kgCode) = execCmdEx(&"{keygenBin} -o {identPath.quoteShell}")
doAssert kgCode == 0, &"age-keygen failed:\n{kgOut}"
var recipient = ""
for line in readFile(identPath).splitLines:
  if line.startsWith("# public key: "):
    recipient = line.split(": ")[1].strip()
doAssert recipient.startsWith("age1"), &"no recipient parsed from {identPath}"

# ssh key used only to sign the manifest
let signKey = work / "signkey"
let (skOut, skCode) = execCmdEx(
  &"ssh-keygen -q -t ed25519 -N '' -f {signKey.quoteShell} -C nimvault-age-test")
doAssert skCode == 0, &"ssh-keygen failed:\n{skOut}"
let allowed = work / "allowed_signers"
writeFile(allowed, "nimvault-age-test " & readFile(signKey & ".pub").strip() & "\n")

writeFile(work / ".vault" / "config", &"""
recipient = {recipient}
root = repo
backend = age
identity = {identPath}
signer = ssh
sign_key = {signKey}
allowed_signers = {allowed}
signer_identity = nimvault-age-test
""")

let cfg = initGpgConfig("", work)
doAssert cfg.backend == "age", "config should select the age backend"
doAssert cfg.usesAge, "usesAge should follow the backend"
doAssert not cfg.signaturesInBand, "age carries no in-band signature"
echo "PASS: age config resolves"

const nimExe = getCurrentCompilerExe()
const srcRoot = currentSourcePath().parentDir.parentDir

proc buildCli(): string =
  result = createTempDir("nimvault_age_", "_bin")
  let (output, code) = execCmdEx(nimExe.quoteShell & " c --hints:off " &
    "--verbosity:0 -p:" & (srcRoot / "src").quoteShell & " -o:" &
    (result / "nimvault").quoteShell & " " &
    (srcRoot / "src" / "nimvault.nim").quoteShell)
  doAssert code == 0, output

var sharedCliDir = ""

proc cliExe(): string =
  if sharedCliDir.len == 0:
    sharedCliDir = buildCli()
  sharedCliDir / "nimvault"

proc runCliTimeout(dir: string, timeoutSec: int,
                   args: seq[string]): tuple[outp: string, code: int] =
  let p = startProcess("timeout", workingDir = dir,
                       args = @["--preserve-status", &"{timeoutSec}s", cliExe()] & args,
                       options = {poUsePath, poStdErrToStdOut})
  result.outp = p.outputStream.readAll()
  result.code = p.waitForExit()
  p.close()

proc ageDecryptSwapHook(realAge: string): string =
  ## Wrapper that runs one swap command when age decrypts a blob by path.
  """#!/bin/sh
set -eu
last=""
for arg in "$@"; do last="$arg"; done
case " $* " in
  *" -d "*) decrypt=1 ;;
  *) decrypt="" ;;
esac
if [ -n "$decrypt" ] && [ -n "${NIMVAULT_SWAP_CMD:-}" ] &&
   [ ! -e "${NIMVAULT_SWAP_MARKER:-}" ]; then
  base="${last##*/}"
  case "$base" in
    [0-9a-f]*.age)
      NIMVAULT_DECRYPT_TARGET="$last" sh -c "$NIMVAULT_SWAP_CMD"
      : >"$NIMVAULT_SWAP_MARKER"
      ;;
  esac
fi
exec """ & realAge.quoteShell & """ "$@"
"""

createDir(work / "secrets")
let secret = work / "secrets" / "tok.txt"
let secretText = "age-backend-round-trip"
writeFile(secret, secretText)

block addAndSeal:
  add(work, secret, cfg)
  seal(work, cfg)
  let entries = loadManifest(work, cfg = cfg)
  doAssert entries.len == 1
  doAssert fileExists(crypto.blobPath(work, cfg, entries[0].id)),
           "blob should carry the age extension"
  doAssert fileExists(manifestPath(work, cfg) & ".sig"),
           "manifest should be signed"
  echo "PASS: age add + seal produce an age blob and a signed manifest"

block signatureTracksTheLatestRecord:
  # Incremental seal leaves the combined stub (and its signature) alone
  # when nothing changed. A leftover stub signature is therefore not a
  # bug: the stub has the same bytes. The per-entry record is the trust
  # root. age encryption is non-deterministic, so a real rewrite must
  # replace that record's detached signature.
  let stubSig = manifestPath(work, cfg) & ".sig"
  let beforeStub = readFile(stubSig)
  seal(work, cfg)
  doAssert readFile(stubSig) == beforeStub,
           "no-op seal must leave the stub signature alone"
  discard loadManifest(work, verifySig = true, cfg = cfg)

  writeFile(secret, secretText & "-changed")
  let entries = loadManifest(work, cfg = cfg)
  doAssert entries.len == 1
  let recSig = entryFile(work, cfg, entries[0].id) & ".sig"
  doAssert fileExists(recSig), "age records carry a detached signature"
  let beforeRec = readFile(recSig)
  seal(work, cfg)
  doAssert readFile(recSig) != beforeRec,
           "resealing a changed file must replace the record signature"
  discard loadManifest(work, verifySig = true, cfg = cfg)
  writeFile(secret, secretText)
  seal(work, cfg)
  echo "PASS: no-op keeps the stub; a rewrite replaces the record signature"

block signingFailureKeepsTheVaultReadable:
  ## The new record must not land under the old signature, or without one.
  ## A key path that is missing fails before ssh-keygen runs; a key file that
  ## is not a key fails inside it, after the old signature would be gone.
  let garbage = work / "not-a-key"
  writeFile(garbage, "not an ssh key\n")
  setFilePermissions(garbage, {fpUserRead, fpUserWrite})
  for badKey in [work / "no-such-key", garbage]:
    writeFile(secret, secretText & "-unsigned-edit")
    var broken = cfg
    broken.signKey = badKey
    var raised = false
    try:
      seal(work, broken)
    except CatchableError:
      raised = true
    doAssert raised, "seal must fail when the record cannot be signed"
    discard loadManifest(work, verifySig = true, cfg = cfg)
    doAssert get(work, secret, cfg).strip() == secretText,
      "a failed signature must leave the previous record and blob readable"
    for kind, path in walkDir(entryDir(work)):
      doAssert not path.endsWith(".tmp") and not path.endsWith(".tmp.sig"),
        "a failed signature must not leave a temporary record: " & path
  writeFile(secret, secretText)
  seal(work, cfg)
  discard loadManifest(work, verifySig = true, cfg = cfg)
  echo "PASS: a signing failure leaves the vault readable"

block unsealAndGet:
  removeFile(secret)
  unseal(work, cfg)
  doAssert fileExists(secret), "unseal should restore the entry"
  doAssert readFile(secret).strip() == secretText
  echo "PASS: age unseal restores through a verified manifest"

  doAssert get(work, secret, cfg).strip() == secretText
  echo "PASS: age get reads a single entry"

block tamperedRecordIsRefused:
  # Split records are the trust root. The combined stub can be rewritten
  # by another machine; a bad signature on an entry record cannot.
  let entries = loadManifest(work, cfg = cfg)
  doAssert entries.len == 1
  let rec = entryFile(work, cfg, entries[0].id)
  let original = readFile(rec)
  writeFile(rec, original & "tamper")
  var raised = false
  try:
    discard loadManifest(work, verifySig = true, cfg = cfg)
  except CatchableError:
    raised = true
  doAssert raised, "a modified entry record must not verify"
  writeFile(rec, original)
  echo "PASS: age refuses a tampered entry record"

proc freshAgeVault(): (string, GpgConfig) =
  ## Another vault under the same identity and signing key, so a block can
  ## tamper with it without disturbing the round trip above.
  let dir = createTempDir("nimvault_age_", "_vault")
  discard execCmdEx(&"git init -q {dir.quoteShell}")
  createDir(dir / ".vault")
  writeFile(dir / ".vault" / "config", readFile(work / ".vault" / "config"))
  (dir, initGpgConfig("", dir))

proc sshVerifySwapHook(realSshKeygen: string): string =
  ## Wrapper that runs one swap command after a successful `ssh-keygen -Y verify`.
  """#!/bin/sh
set -u
sig=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-s" ]; then
    sig="$arg"
  fi
  prev="$arg"
done
""" & realSshKeygen.quoteShell & """ "$@"
code=$?
if [ "$code" -eq 0 ] && [ -n "${NIMVAULT_SWAP_CMD:-}" ] &&
   [ -n "${NIMVAULT_SWAP_MARKER:-}" ] &&
   [ ! -e "${NIMVAULT_SWAP_MARKER}" ] && [ -n "$sig" ]; then
  NIMVAULT_VERIFY_TARGET="${sig%.sig}" sh -c "$NIMVAULT_SWAP_CMD"
  : >"$NIMVAULT_SWAP_MARKER"
fi
exit "$code"
"""

block splitRecordSwapDuringSshVerifyIsRefused:
  ## age split-record loads must decrypt the same bytes ssh-keygen verified.
  let (dir, c) = freshAgeVault()
  let f = dir / "tok.txt"
  writeFile(f, "age-split-original")
  add(dir, f, c)
  seal(dir, c)
  removeFile(f)
  let entry = loadManifest(dir, cfg = c)[0]
  let blob = crypto.blobPath(dir, c, entry.id)
  let dek = loadDeks(dir, c)[entry.id]
  let forged = createTempDir("nimvault_age_", "_forged")
  let payload = forged / "payload.txt"
  writeFile(payload, "PWNED-PLAINTEXT")
  let badBlob = forged / "blob.age"
  encryptWithDek(c, dek, payload, badBlob)
  let badHash = sha256sum(badBlob)
  let plain = forged / "record.plain"
  writeFile(plain, EntryHeader & "\n" &
    &"{entry.id}\t{entry.path}\t{badHash}\tfile\t{sha256sum(payload)}\t{dek}\n")
  let badRec = forged / "record.age"
  encryptFileTo(c, @[c.recipient], plain, badRec, sign = false)

  let wrapBin = createTempDir("nimvault_age_", "_sshwrap")
  let marker = wrapBin / "swapped"
  let wrapper = wrapBin / "ssh-keygen"
  let realSsh = findExe("ssh-keygen")
  doAssert realSsh.len > 0
  writeFile(wrapper, sshVerifySwapHook(realSsh))
  setFilePermissions(wrapper, {fpUserRead, fpUserWrite, fpUserExec})
  let swapCmd = "cat " & badRec.quoteShell & " > \"$NIMVAULT_VERIFY_TARGET\"" &
                " && cat " & badBlob.quoteShell & " > " & blob.quoteShell
  let oldPath = getEnv("PATH")
  putEnv("PATH", wrapBin & ":" & oldPath)
  putEnv("NIMVAULT_SWAP_CMD", swapCmd)
  putEnv("NIMVAULT_SWAP_MARKER", marker)
  var raised = false
  try:
    unseal(dir, c)
  except CatchableError:
    raised = true
  finally:
    putEnv("PATH", oldPath)
    delEnv("NIMVAULT_SWAP_CMD")
    delEnv("NIMVAULT_SWAP_MARKER")
  doAssert fileExists(marker), "test wrapper did not swap the verified record"
  doAssert raised, "unseal must fail after a split-record swap post-verify"
  doAssert not fileExists(f), "unseal must not write plaintext after the swap"
  removeDir(dir)
  removeDir(forged)
  removeDir(wrapBin)
  echo "PASS: age split-record swaps after verify are refused"

block legacyManifestSwapDuringSshVerifyIsRefused:
  ## Legacy combined manifests must not verify one read and decrypt another.
  let (dir, c) = freshAgeVault()
  let f = dir / "tok.txt"
  writeFile(f, "age-legacy-original")
  add(dir, f, c)
  seal(dir, c)
  let entry = loadManifest(dir, cfg = c)[0]
  let blob = crypto.blobPath(dir, c, entry.id)
  let dek = loadDeks(dir, c)[entry.id]
  if dirExists(entryDir(dir)):
    removeDir(entryDir(dir))
  saveManifest(dir, @[entry], c)
  doAssert not hasSplitEntries(dir), "test setup must use the legacy read path"
  removeFile(f)

  let forged = createTempDir("nimvault_age_", "_legacy_forged")
  let payload = forged / "payload.txt"
  writeFile(payload, "PWNED-PLAINTEXT")
  let badBlob = forged / "blob.age"
  encryptWithDek(c, dek, payload, badBlob)
  let badHash = sha256sum(badBlob)
  let badTarget = "secrets/evil.txt"
  let badPlain = forged / "manifest.plain"
  writeFile(badPlain, "# vault-manifest-v4\n" &
    &"{entry.id}\t{badTarget}\t{badHash}\tfile\t{sha256sum(payload)}\n")
  let badManifest = forged / "manifest.age"
  encryptFile(c, badPlain, badManifest)

  let wrapBin = createTempDir("nimvault_age_", "_sshwrap")
  let marker = wrapBin / "swapped"
  let wrapper = wrapBin / "ssh-keygen"
  let realSsh = findExe("ssh-keygen")
  doAssert realSsh.len > 0
  writeFile(wrapper, sshVerifySwapHook(realSsh))
  setFilePermissions(wrapper, {fpUserRead, fpUserWrite, fpUserExec})
  let swapCmd = "cat " & badManifest.quoteShell & " > \"$NIMVAULT_VERIFY_TARGET\"" &
                " && cat " & badBlob.quoteShell & " > " & blob.quoteShell
  let oldPath = getEnv("PATH")
  putEnv("PATH", wrapBin & ":" & oldPath)
  putEnv("NIMVAULT_SWAP_CMD", swapCmd)
  putEnv("NIMVAULT_SWAP_MARKER", marker)
  var raised = false
  try:
    unseal(dir, c)
  except CatchableError:
    raised = true
  finally:
    putEnv("PATH", oldPath)
    delEnv("NIMVAULT_SWAP_CMD")
    delEnv("NIMVAULT_SWAP_MARKER")
  doAssert fileExists(marker), "test wrapper did not swap the verified manifest"
  doAssert raised, "unseal must fail after a legacy-manifest swap post-verify"
  doAssert not fileExists(dir / badTarget),
    "unseal must not write attacker plaintext from a swapped manifest"
  doAssert not fileExists(f), "unseal must not restore plaintext after the swap"
  removeDir(dir)
  removeDir(forged)
  removeDir(wrapBin)
  echo "PASS: age legacy-manifest swaps after verify are refused"

block ageGetDecryptsVerifiedSnapshotBytes:
  ## A swap hook can only replace a decrypt path argument. `get` must decrypt
  ## the ciphertext bytes it already hashed.
  let (dir, c) = freshAgeVault()
  let f = dir / "tok.txt"
  let plain = "age-snapshot-original"
  writeFile(f, plain)
  add(dir, f, c)
  seal(dir, c)
  removeFile(f)
  let entry = loadManifest(dir, cfg = c)[0]
  let dek = loadDeks(dir, c)[entry.id]
  let forged = createTempDir("nimvault_age_", "_forged")
  let payload = forged / "payload.txt"
  writeFile(payload, "PWNED-PLAINTEXT")
  let badBlob = forged / "blob.age"
  encryptWithDek(c, dek, payload, badBlob)

  let wrapBin = createTempDir("nimvault_age_", "_agewrap")
  let marker = wrapBin / "swapped"
  let wrapper = wrapBin / "age"
  let realAge = findExe(ageBin)
  doAssert realAge.len > 0
  writeFile(wrapper, ageDecryptSwapHook(realAge))
  setFilePermissions(wrapper, {fpUserRead, fpUserWrite, fpUserExec})
  let swapCmd = "cat " & badBlob.quoteShell & " > \"$NIMVAULT_DECRYPT_TARGET\""
  let oldPath = getEnv("PATH")
  putEnv("PATH", wrapBin & ":" & oldPath)
  putEnv("NIMVAULT_SWAP_CMD", swapCmd)
  putEnv("NIMVAULT_SWAP_MARKER", marker)
  let got = get(dir, f, c)
  putEnv("PATH", oldPath)
  delEnv("NIMVAULT_SWAP_CMD")
  delEnv("NIMVAULT_SWAP_MARKER")
  doAssert got == plain, got
  doAssert not fileExists(marker),
    "age decrypt should not reopen a blob path during get"
  removeDir(dir)
  removeDir(forged)
  removeDir(wrapBin)
  echo "PASS: age get decrypts verified snapshot bytes"

block legacyAgeGetDecryptsVerifiedSnapshotBytes:
  ## A legacy combined manifest plus unsigned keys file must still decrypt the
  ## bytes that were hashed, not a swapped decrypt path.
  let (dir, c) = freshAgeVault()
  let f = dir / "tok.txt"
  let plain = "age-legacy-snapshot-original"
  writeFile(f, plain)
  add(dir, f, c)
  seal(dir, c)
  let entry = loadManifest(dir, cfg = c)[0]
  let dek = loadDeks(dir, c)[entry.id]
  if dirExists(entryDir(dir)):
    removeDir(entryDir(dir))
  saveManifest(dir, @[entry], c)
  doAssert not hasSplitEntries(dir), "test setup must use the legacy read path"
  removeFile(f)

  let forged = createTempDir("nimvault_age_", "_legacy_forged")
  let payload = forged / "payload.txt"
  writeFile(payload, "PWNED-PLAINTEXT")
  let badBlob = forged / "blob.age"
  encryptWithDek(c, dek, payload, badBlob)

  let wrapBin = createTempDir("nimvault_age_", "_agewrap")
  let marker = wrapBin / "swapped"
  let wrapper = wrapBin / "age"
  let realAge = findExe(ageBin)
  doAssert realAge.len > 0
  writeFile(wrapper, ageDecryptSwapHook(realAge))
  setFilePermissions(wrapper, {fpUserRead, fpUserWrite, fpUserExec})
  let swapCmd = "cat " & badBlob.quoteShell & " > \"$NIMVAULT_DECRYPT_TARGET\""
  let oldPath = getEnv("PATH")
  putEnv("PATH", wrapBin & ":" & oldPath)
  putEnv("NIMVAULT_SWAP_CMD", swapCmd)
  putEnv("NIMVAULT_SWAP_MARKER", marker)
  let got = get(dir, f, c)
  putEnv("PATH", oldPath)
  delEnv("NIMVAULT_SWAP_CMD")
  delEnv("NIMVAULT_SWAP_MARKER")
  doAssert got == plain, got
  doAssert not fileExists(marker),
    "legacy age decrypt should not reopen a blob path during get"
  removeDir(dir)
  removeDir(forged)
  removeDir(wrapBin)
  echo "PASS: legacy age get decrypts verified snapshot bytes"

block ageLargeCipherDecryptsWithoutDeadlock:
  ## Deadlock regression: stdin is now fed while stdout is drained.
  let (dir, c) = freshAgeVault()
  let medium = dir / "medium.txt"
  let mediumPlain = repeat('M', 300_000)
  writeFile(medium, mediumPlain)
  add(dir, medium, c)
  seal(dir, c)
  let midEntry = loadManifest(dir, cfg = c)[0]
  let midBlob = crypto.blobPath(dir, c, midEntry.id)
  doAssert int(getFileSize(midBlob)) == 300_264,
    "test seam expects the 300264-byte ciphertext case"
  removeFile(medium)
  var got = runCliTimeout(dir, 15, @["get", "medium.txt"])
  doAssert got.code == 0, got.outp
  doAssert got.outp.len == mediumPlain.len
  remove(dir, medium, c)

  let big = dir / "big.txt"
  let bigPlain = repeat('B', 2_000_000)
  writeFile(big, bigPlain)
  add(dir, big, c)
  seal(dir, c)
  removeFile(big)
  got = runCliTimeout(dir, 20, @["get", "big.txt"])
  doAssert got.code == 0, got.outp
  doAssert got.outp.len == bigPlain.len

  let (listDir, lc) = freshAgeVault()
  var many: seq[VaultEntry] = @[]
  for i in 0 ..< 1500:
    let id = toHex(i, 16).toLowerAscii()
    let path = "bulk/" & repeat('x', 120) & "/" & $i & ".txt"
    many.add((id, path, repeat('a', 64), ekFile, repeat('b', 64)))
  saveManifest(listDir, many, lc, sealKey(lc))
  got = runCliTimeout(listDir, 20, @["list"])
  doAssert got.code == 0, got.outp
  doAssert "bulk/" in got.outp

  let (addDir, ac) = freshAgeVault()
  let keep = addDir / "keep.txt"
  writeFile(keep, "keep")
  add(addDir, keep, ac)
  seal(addDir, ac)
  let keepEntry = loadManifest(addDir, cfg = ac)[0]
  let keepDek = loadDeks(addDir, ac)[keepEntry.id]
  if dirExists(entryDir(addDir)):
    removeDir(entryDir(addDir))
  saveManifest(addDir, @[keepEntry], ac)
  let keys = keyFiles(addDir, ac)
  doAssert keys.len > 0
  let keyWork = createTempDir("nimvault_age_", "_keys")
  let keyPlain = keyWork / "keys.plain"
  var keyContent = "# vault-keys-v6\n" & keepEntry.id & "\t" & keepDek & "\n"
  for i in 0 ..< 3800:
    keyContent.add(&"{toHex(i + 1_000_000, 16).toLowerAscii()}\t{repeat('f', 64)}\n")
  writeFile(keyPlain, keyContent)
  encryptFileTo(ac, @[ac.recipient], keyPlain, keys[0], sign = false)
  removeDir(keyWork)
  let later = addDir / "later.txt"
  writeFile(later, "later")
  got = runCliTimeout(addDir, 20, @["add", "later.txt"])
  doAssert got.code == 0, got.outp
  doAssert "later.txt" in got.outp

  removeDir(dir)
  removeDir(listDir)
  removeDir(addDir)
  echo "PASS: age large-cipher paths return under timeout"

block allowUnsignedStillVerifiesAPresentSshSignature:
  ## --allow-unsigned accepts a record with no detached signature. A record
  ## signed by a key outside allowed_signers is not unsigned.
  let (dir, c) = freshAgeVault()
  let f = dir / "tok.txt"
  writeFile(f, "age-flag")
  add(dir, f, c)
  seal(dir, c)
  let rec = entryFile(dir, c, loadManifest(dir, cfg = c)[0].id)
  let otherKey = work / "otherkey"
  let (kout, kcode) = execCmdEx(
    &"ssh-keygen -q -t ed25519 -N '' -f {otherKey.quoteShell} -C other")
  doAssert kcode == 0, kout
  removeFile(rec & ".sig")
  let (sout, scode) = execCmdEx(
    &"ssh-keygen -Y sign -f {otherKey.quoteShell} -n nimvault {rec.quoteShell}")
  doAssert scode == 0, sout
  removeFile(f)
  var raised = false
  try:
    unseal(dir, c, allowUnsigned = true)
  except CatchableError as e:
    raised = true
    doAssert "signature verification failed" in e.msg, e.msg
  doAssert raised, "unseal --allow-unsigned must refuse a signer outside allowed_signers"
  doAssert not fileExists(f)
  raised = false
  try:
    discard get(dir, f, c, allowUnsigned = true)
  except CatchableError:
    raised = true
  doAssert raised, "get --allow-unsigned must refuse a signer outside allowed_signers"
  removeFile(rec & ".sig")
  raised = false
  try:
    unseal(dir, c)
  except CatchableError:
    raised = true
  doAssert raised, "unseal without the flag must refuse a missing signature"
  unseal(dir, c, allowUnsigned = true)
  doAssert readFile(f).strip() == "age-flag", "the flag accepts a missing signature"
  removeDir(dir)
  echo "PASS: age --allow-unsigned verifies a detached signature that is present"

block ageWithAGpgSignerIsRefused:
  ## gpg signs only what it encrypts, so `signer = gpg` on an age vault signed
  ## and verified nothing. With that one config line, an unsigned record built
  ## from the public recipient went through a plain unseal.
  let (dir, c) = freshAgeVault()
  let f = dir / "tok.txt"
  writeFile(f, "age-honest")
  add(dir, f, c)
  seal(dir, c)
  let id = "fefefefefefefefe"
  let scratch = createTempDir("nimvault_age_", "_forge")
  let payload = scratch / "payload"
  writeFile(payload, "planted")
  let key = newDek(c)
  let blob = crypto.blobPath(dir, c, id)
  encryptWithDek(c, key, payload, blob)
  let plain = scratch / "record.plain"
  writeFile(plain, EntryHeader & "\n" &
    &"{id}\tplanted.txt\t{sha256sum(blob)}\tfile\t{sha256sum(payload)}\t{key}\n")
  encryptFileTo(c, @[c.recipient], plain, entryFile(dir, c, id), sign = false)
  removeDir(scratch)

  let config = readFile(dir / ".vault" / "config")
  proc loadError(text: string): string =
    writeFile(dir / ".vault" / "config", text)
    try:
      discard initGpgConfig("", dir)
    except CatchableError as e:
      return e.msg
  doAssert "signer = gpg does not sign an age vault" in
    loadError(config.replace("signer = ssh", "signer = gpg"))
  doAssert "unknown signer" in loadError(config.replace("signer = ssh", "signer = sshh"))
  doAssert "unknown backend" in loadError(config.replace("backend = age", "backend = agee"))
  doAssert loadError(config.replace("signer = ssh", "signer = none")) == ""
  writeFile(dir / ".vault" / "config", config)

  var bypass = c
  bypass.signer = "gpg"
  removeFile(f)
  var msg = ""
  try:
    unseal(dir, bypass)
  except CatchableError as e:
    msg = e.msg
  doAssert "does not sign an age vault" in msg,
    "an age vault with signer = gpg unsealed: " & msg
  doAssert not fileExists(dir / "planted.txt") and not fileExists(f)
  msg = ""
  try:
    check(dir, bypass)
  except CatchableError as e:
    msg = e.msg
  doAssert "does not sign an age vault" in msg, "check passed: " & msg
  writeFile(f, "age-edit")
  msg = ""
  try:
    seal(dir, bypass)
  except CatchableError as e:
    msg = e.msg
  doAssert "does not sign an age vault" in msg, "seal wrote an unsigned record: " & msg
  removeDir(dir)
  echo "PASS: an age vault refuses signer = gpg"

block missingSshSignerSettingsFail:
  ## A record whose signature could not be checked was skipped uncounted, so
  ## unseal reported an empty vault and check asked for a secret key.
  let (dir, c) = freshAgeVault()
  let f = dir / "tok.txt"
  writeFile(f, "age-settings")
  add(dir, f, c)
  seal(dir, c)
  removeFile(f)
  var noAllowed = c
  noAllowed.allowedSigners = ""
  var lostAllowed = c
  lostAllowed.allowedSigners = dir / "no-such-allowed-signers"
  var noIdentity = c
  noIdentity.signerIdentity = ""
  for (broken, want) in [(noAllowed, "no allowed_signers"),
                         (lostAllowed, "allowed_signers not found"),
                         (noIdentity, "no signer_identity")]:
    var msg = ""
    try:
      unseal(dir, broken)
    except CatchableError as e:
      msg = e.msg
    doAssert want in msg, "unseal: " & want & ": " & msg
    doAssert not fileExists(f)
    msg = ""
    try:
      check(dir, broken)
    except CatchableError as e:
      msg = e.msg
    doAssert want in msg, "check: " & want & ": " & msg
  unseal(dir, c)
  doAssert readFile(f).strip() == "age-settings"
  removeDir(dir)
  echo "PASS: missing ssh signer settings fail unseal and check"

if sharedCliDir.len > 0:
  removeDir(sharedCliDir)
removeDir(work)
echo "All age backend tests passed."
