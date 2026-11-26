## A public recipient must not turn an unsigned fragment into a signed entry.
##
## On a signer-configured age vault, NIMVAULT_PUBLIC_ONLY can append. The
## owner check has to fail, get must not return the plant, and unseal must
## not let a later duplicate path replace the signed plaintext.

import std/[os, osproc, strutils, strformat, tempfiles]
import nimvault/[gpg, manifest, commands]

proc have(bin: string): bool = findExe(bin).len > 0

if not (have("age") or have("rage")) or not have("ssh-keygen"):
  echo "SKIP: downgrade tests (age or ssh-keygen not installed)"
  quit(0)

let keygenBin = if have("age-keygen"): "age-keygen" else: "rage-keygen"
if not have(keygenBin):
  echo "SKIP: downgrade tests (no age-keygen)"
  quit(0)

let work = createTempDir("nimvault_down_", "_test")
discard execCmdEx(&"git init -q {work.quoteShell}")
createDir(work / ".vault")

let identPath = work / "id.txt"
let (kgOut, kgCode) = execCmdEx(&"{keygenBin} -o {identPath.quoteShell}")
doAssert kgCode == 0, kgOut
var recipient = ""
for line in readFile(identPath).splitLines:
  if line.startsWith("# public key: "):
    recipient = line.split(": ")[1].strip()
doAssert recipient.startsWith("age1"), recipient

let signKey = work / "signkey"
let (skOut, skCode) = execCmdEx(
  &"ssh-keygen -q -t ed25519 -N '' -f {signKey.quoteShell} -C nimvault-down-test")
doAssert skCode == 0, skOut
let allowed = work / "allowed_signers"
writeFile(allowed, "nimvault-down-test " & readFile(signKey & ".pub").strip() & "\n")
writeFile(work / ".vault" / "config", &"""
recipient = {recipient}
root = repo
backend = age
identity = {identPath}
signer = ssh
sign_key = {signKey}
allowed_signers = {allowed}
signer_identity = nimvault-down-test
""")

let cfg = initGpgConfig("", work)
let real = work / "real.txt"
let evil = work / "evil.txt"
writeFile(real, "SIGNED")
add(work, real, cfg)
seal(work, cfg)

putEnv("NIMVAULT_PUBLIC_ONLY", "1")
try:
  writeFile(evil, "FORGED")
  writeFile(real, "FORGED2")
  add(work, evil, cfg)
  add(work, real, cfg)
  seal(work, cfg)
finally:
  putEnv("NIMVAULT_PUBLIC_ONLY", "")

let rep = checkVault(work, cfg)
let joined = rep.problems.join("\n")
doAssert rep.problems.len > 0, "check accepted unsigned appends: " & joined
doAssert "not signed" in joined, joined
doAssert "duplicates signed path" in joined, joined

var code = 0
try:
  code = check(work, cfg)
except NimvaultError as e:
  code = e.code
doAssert code != 0, "owner check exit " & $code

var body = ""
var msg = ""
try:
  body = get(work, evil, cfg)
except CatchableError as e:
  msg = e.msg
doAssert body != "FORGED", "get returned the planted fragment"
doAssert "not signed" in msg or "unsigned" in msg, msg

removeFile(evil)
unseal(work, cfg)
doAssert readFile(real) == "SIGNED", "unseal wrote " & readFile(real)
doAssert not fileExists(evil), "unseal restored the planted path"
echo "PASS: unsigned appends are not signed entries"

block missingAgeIdentityDoesNotPassCheck:
  ## No identity file is not --public-only. The blob-index still matches the
  ## plant, which is why that index is not a tamper signal.
  let writer = GpgConfig(recipient: recipient, root: work, backend: "age")
  let missing = checkVault(work, writer)
  doAssert missing.problems.len > 0, $missing.problems
  doAssert "no decrypt key" in missing.problems.join("\n"), $missing.problems
  var explicit = writer
  explicit.publicOnly = true
  doAssert checkVault(work, explicit).problems.len == 0,
    "blob-index matches a plant the writer indexed: " &
    $checkVault(work, explicit).problems
  echo "PASS: missing age identity does not pass check"

block deletedIndexIsNotAnEmptyVault:
  let vault = work / ".vault"
  for kind, path in walkDir(vault):
    if kind != pcFile: continue
    let name = path.extractFilename
    if name == "config" or name.startsWith("manifest") or name.startsWith("keys"):
      continue
    removeFile(path)
  for sub in [vault / "e", vault / "a"]:
    if not dirExists(sub): continue
    for kind, path in walkDir(sub):
      if kind == pcFile: removeFile(path)
  var pub = GpgConfig(recipient: recipient, root: work, backend: "age",
                      publicOnly: true)
  let wiped = checkVault(work, pub)
  let text = wiped.problems.join("\n")
  doAssert wiped.problems.len > 0, "wiped vault looked empty: " & text
  doAssert "not an empty vault" in text, text
  let dig = work / "after-wipe.txt"
  writeDigestFile(dig, vaultCipherDigests(work))
  let again = checkVault(work, pub, dig)
  doAssert again.problems.len == 0, $again.problems
  echo "PASS: deleted blob-index and records are not an empty vault"

removeDir(work)
echo "All downgrade tests passed."
