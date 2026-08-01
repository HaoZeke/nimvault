## Round-trip for the age backend with a detached ssh signature.
##
## Skips itself when `age` or `ssh-keygen` is absent rather than failing, so the
## suite still runs on a machine that only has gpg. A skip is announced, since a
## test that quietly does nothing is worse than one that is not there.

import std/[os, osproc, strutils, strformat, tempfiles]
import nimvault/[gpg, manifest, commands, crypto]

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

block signatureTracksTheLatestManifest:
  # Both add and seal save the manifest, and age encryption is
  # non-deterministic, so the second save produces different ciphertext. A
  # signature left over from the first would describe content that no longer
  # exists, and every command would still report success.
  let sig = manifestPath(work, cfg) & ".sig"
  let before = readFile(sig)
  seal(work, cfg)
  doAssert readFile(sig) != before,
           "re-sealing must replace the signature, not leave a stale one"
  echo "PASS: re-sealing replaces the signature"

block unsealAndGet:
  removeFile(secret)
  unseal(work, cfg)
  doAssert fileExists(secret), "unseal should restore the entry"
  doAssert readFile(secret).strip() == secretText
  echo "PASS: age unseal restores through a verified manifest"

  doAssert get(work, secret, cfg).strip() == secretText
  echo "PASS: age get reads a single entry"

block tamperedManifestIsRefused:
  # The signature is the only thing standing between a rewritten manifest and a
  # trusted one, since age blobs carry no signature of their own.
  let mpath = manifestPath(work, cfg)
  let original = readFile(mpath)
  writeFile(mpath, original & "tamper")
  var raised = false
  try:
    discard loadManifest(work, verifySig = true, cfg = cfg)
  except CatchableError:
    raised = true
  doAssert raised, "a modified manifest must not verify"
  writeFile(mpath, original)
  echo "PASS: age refuses a tampered manifest"

removeDir(work)
echo "All age backend tests passed."
