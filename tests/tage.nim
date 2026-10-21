## Round-trip for the age backend with a detached ssh signature.
##
## Skips itself when `age` or `ssh-keygen` is absent rather than failing, so the
## suite still runs on a machine that only has gpg. A skip is announced, since a
## test that quietly does nothing is worse than one that is not there.

import std/[os, osproc, strutils, strformat, tempfiles]
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

removeDir(work)
echo "All age backend tests passed."
