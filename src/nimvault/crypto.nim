## Backend dispatch: route encryption and decryption to gpg or age.
##
## Kept in its own module so neither backend has to know the other exists, and
## so the choice is made in exactly one place rather than at each call site.

import std/[os, osproc, streams, strformat, strutils, posix, sysrand]
from ./gpg import GpgConfig, nvRaise, gpgEncrypt, gpgDecrypt, gpgDecryptToString,
                  gpgStatusHas, gpgParallelism, sha256sum, gpgVerdict, vaultSigners,
                  signingKey, AgeGpgSigner
from ./age import ageEncrypt, ageDecrypt, ageDecryptToString, sshSign,
                  sshVerify, ageBinary, ageIdentityPath
from ./fsat import ONoFollow

proc ensureOwnerDir*(dir: string) =
  ## Create `dir` mode 0700, or tighten a directory this user already owns.
  ## A symlink or another uid's directory is refused: plaintext and data keys
  ## are written underneath it.
  if symlinkExists(dir):
    nvRaise(&"FATAL: refusing runtime directory symlink: {dir}")
  if not dirExists(dir):
    if posix.mkdir(dir.cstring, 0o700.Mode) != 0 and posix.errno != posix.EEXIST:
      nvRaise(&"FATAL: cannot create runtime directory: {dir}")
  if symlinkExists(dir):
    nvRaise(&"FATAL: refusing runtime directory symlink: {dir}")
  var st: posix.Stat
  if posix.lstat(dir.cstring, st) != 0:
    nvRaise(&"FATAL: cannot stat runtime directory: {dir}")
  if posix.S_ISLNK(st.st_mode):
    nvRaise(&"FATAL: refusing runtime directory symlink: {dir}")
  if not posix.S_ISDIR(st.st_mode):
    nvRaise(&"FATAL: runtime directory is not a directory: {dir}")
  if st.st_uid != posix.getuid():
    nvRaise(&"FATAL: runtime directory is not owned by this user: {dir}")
  if posix.chmod(dir.cstring, 0o700.Mode) != 0:
    nvRaise(&"FATAL: cannot restrict runtime directory: {dir}")

proc privateWorkDir*(): string =
  ## Owner-only directory for plaintext and data keys that must not land in
  ## `.vault/` or under a shared `/tmp` name. Prefer `$XDG_RUNTIME_DIR` so
  ## the bytes die with the login; fall back to a 0700 directory named by
  ## uid under the process temp area.
  let xdg = getEnv("XDG_RUNTIME_DIR")
  let parent =
    if xdg.len > 0 and dirExists(xdg): xdg / "nimvault"
    else: getTempDir() / &"nimvault-{getuid()}"
  ensureOwnerDir(parent)
  var buf: array[8, byte]
  doAssert urandom(buf)
  var id = ""
  for b in buf:
    id.add(b.toHex(2).toLowerAscii())
  result = parent / id
  if posix.mkdir(result.cstring, 0o700.Mode) != 0:
    nvRaise(&"FATAL: cannot create work directory: {result}")
  setFilePermissions(result, {fpUserRead, fpUserWrite, fpUserExec})

proc shredFile*(path: string) =
  ## Overwrite a regular file, then unlink it. A symlink is unlinked and not
  ## followed. Best effort: a filesystem that keeps old blocks can still
  ## recover them.
  if path.len == 0:
    return
  if symlinkExists(path):
    try: removeFile(path) except CatchableError: discard
    return
  if not fileExists(path):
    return
  let fd = posix.open(path.cstring, posix.O_WRONLY or ONoFollow)
  if fd >= 0:
    var left = getFileSize(path)
    var buf: array[8192, byte]
    while left > 0:
      let n = min(left.int, buf.len)
      if not urandom(buf):
        for i in 0 ..< buf.len: buf[i] = 0
      let w = posix.write(fd, addr buf[0], n)
      if w <= 0: break
      left -= w
    discard posix.fsync(fd)
    discard posix.close(fd)
  try: removeFile(path) except CatchableError: discard

proc discardPrivate*(dir: string) =
  ## Shred files under a work directory this process created, then remove it.
  if dir.len == 0 or symlinkExists(dir) or not dirExists(dir):
    return
  for path in walkDirRec(dir, yieldFilter = {pcFile, pcLinkToFile}):
    shredFile(path)
  try: removeDir(dir) except CatchableError: discard

proc renameAt(src, dest: cstring): cint {.importc: "rename", header: "<stdio.h>".}
  ## `rename(2)`. Replaces `dest` when it is a symlink and does not follow it.
  ## Nim's posix module does not wrap this call.

proc publishPending*(src, dest: string) =
  ## Replace `dest` with `src`. A failed rename leaves `src` where it is:
  ## the record may already name those bytes, and deleting them would leave
  ## the record pointing at ciphertext that is no longer on disk.
  if renameAt(src.cstring, dest.cstring) != 0:
    nvRaise(&"FATAL: could not publish blob {dest}")

proc renameOver*(src, dest: string) =
  ## `rename` replaces `dest` even when `dest` is a symlink, and does not
  ## follow it. The copy fallback in `moveFile` does follow, which writes
  ## plaintext through a symlink when the two paths are on different devices.
  if renameAt(src.cstring, dest.cstring) != 0:
    shredFile(src)
    nvRaise(&"FATAL: could not place plaintext at {dest}")

template withPrivateUmask*(body: untyped) =
  ## Decrypt/encrypt sidecars inherit the process umask. Force 077 so a
  ## typical 022 does not leave a world-readable plaintext next to the
  ## destination for the length of the batch.
  let old = posix.umask(0o077.Mode)
  try:
    body
  finally:
    discard posix.umask(old)

proc ensureVaultDir*(repo: string) =
  ## `.vault/` holds ciphertext, but a crash can leave a plaintext sidecar
  ## in it. Mode 0700 means another uid on the box cannot scoop that file.
  let d = repo / ".vault"
  if not dirExists(d):
    createDir(d)
  setFilePermissions(d, {fpUserRead, fpUserWrite, fpUserExec})

proc syncPath*(path: string) =
  ## Flush `path` to stable storage. Best effort: a file system that refuses
  ## the sync is not a reason to fail a command that otherwise succeeded.
  ##
  ## Rename is atomic against a concurrent *reader*, which is a different
  ## property from surviving a crash: the rename can reach disk before the
  ## bytes it points at, leaving a manifest that is present and empty. The
  ## orderings real file systems guarantee here are narrower than the idiom
  ## suggests (Bornholt et al., ASPLOS 2016, doi:10.1145/2872362.2872406;
  ## Chidambaram et al., SOSP 2013, doi:10.1145/2517349.2522726), so the
  ## durability is made explicit rather than assumed.
  let fd = posix.open(path.cstring, O_RDONLY)
  if fd < 0:
    return
  discard fsync(fd)
  discard close(fd)

proc syncParentDir*(path: string) =
  ## Persist the directory entry a rename just created.
  syncPath(path.parentDir)

proc usesAge*(cfg: GpgConfig): bool =
  cfg.backend == "age"

proc blobExt*(cfg: GpgConfig): string =
  ## Blobs and the manifest carry the extension of the primitive that made
  ## them. Giving both backends the same name would make a vault that cannot be
  ## read look like a vault that is empty, which is the worst of the available
  ## failure modes: silent and reassuring.
  if cfg.usesAge: ".age" else: ".gpg"

proc blobPath*(repo: string, cfg: GpgConfig, id: string): string =
  ## Where a blob lives for the configured backend.
  repo / ".vault" / (id & cfg.blobExt)

proc findBlob*(repo: string, cfg: GpgConfig, id: string): string =
  ## Locate a blob whichever backend wrote it. Reading falls back to the other
  ## extension so a vault mid-migration still opens; writing always uses the
  ## configured one.
  let mine = blobPath(repo, cfg, id)
  if fileExists(mine):
    return mine
  let other = repo / ".vault" / (id & (if cfg.usesAge: ".gpg" else: ".age"))
  if fileExists(other):
    return other
  return mine   ## report the expected path in the caller's "missing" error

proc resolveBlob*(repo: string, cfg: GpgConfig, id, expectedHash: string): string =
  ## The live blob when it matches `expectedHash`. A `.pending` sibling is
  ## the ciphertext a seal wrote before it could rename it into place; if
  ## that sibling is the one the record names, promote it.
  let live = findBlob(repo, cfg, id)
  proc matches(path: string): bool =
    expectedHash.len > 0 and fileExists(path) and sha256sum(path) == expectedHash
  let pend = blobPath(repo, cfg, id) & ".pending"
  if matches(live):
    if fileExists(pend):
      try: removeFile(pend) except CatchableError: discard
    return live
  if matches(pend):
    let dest = blobPath(repo, cfg, id)
    if renameAt(pend.cstring, dest.cstring) != 0:
      if matches(dest): return dest
      return live
    syncPath(dest)
    syncParentDir(dest)
    return dest
  return live

proc manifestPath*(repo: string, cfg: GpgConfig): string =
  ## Path the configured backend would write. Use `findManifest` to read.
  repo / ".vault" / ("manifest" & cfg.blobExt)

proc findManifest*(repo: string, cfg: GpgConfig): string =
  ## Locate an existing manifest whichever backend wrote it, and refuse to
  ## treat a manifest this configuration cannot read as an absent one.
  let mine = manifestPath(repo, cfg)
  if fileExists(mine):
    return mine
  let other = repo / ".vault" / ("manifest" & (if cfg.usesAge: ".gpg" else: ".age"))
  if fileExists(other):
    let want = if cfg.usesAge: "gpg" else: "age"
    nvRaise(&"FATAL: this vault was sealed with the {want} backend.\n" &
            &"  Found: {other}\n" &
            &"  Set `backend = {want}` in .vault/config (and its identity or recipient).")
  return ""

proc encryptFile*(cfg: GpgConfig, inPath, outPath: string) =
  if cfg.usesAge: ageEncrypt(cfg, inPath, outPath)
  else: gpgEncrypt(cfg, inPath, outPath)

proc decryptFile*(cfg: GpgConfig, inPath, outPath: string, verifySig = false) =
  ## age carries no signature, so `verifySig` has nothing to check per blob.
  ## That is not a weakening: the manifest records each blob's SHA-256 and the
  ## callers verify it before decrypting, with the manifest itself signed.
  if cfg.usesAge: ageDecrypt(cfg, inPath, outPath)
  else: gpgDecrypt(cfg, inPath, outPath, verifySig)

proc decryptToString*(cfg: GpgConfig, inPath: string, verifySig = false,
                      checkPresent = false): string =
  if cfg.usesAge: ageDecryptToString(cfg, inPath)
  else: gpgDecryptToString(cfg, inPath, verifySig, checkPresent)

type Decrypted* = tuple[plain, err: string]
  ## One file's plaintext, or the message `decryptToString` would have raised.

proc decryptManyToString*(cfg: GpgConfig, paths: seq[string],
                          verifySig = false, checkPresent = false): seq[Decrypted] =
  ## `decryptToString` over many small files, in the same order, with no
  ## raise: each failure comes back as its message. gpg runs
  ## `gpgParallelism()` processes at a time; a vault of a few hundred split
  ## records otherwise pays one process start and one agent round trip per
  ## record, in series, on every command that loads the manifest. age stays
  ## sequential, since its decrypt is in-process fast.
  result = newSeq[Decrypted](paths.len)
  if cfg.usesAge:
    for i, path in paths:
      try:
        result[i] = (ageDecryptToString(cfg, path), "")
      except CatchableError as err:
        result[i] = ("", err.msg)
    return
  let batch = gpgParallelism()
  let allowed = if verifySig or checkPresent: vaultSigners(cfg) else: @[]
  for start in countup(0, paths.high, batch):
    let stop = min(start + batch - 1, paths.high)
    var procs: seq[(int, Process)] = @[]
    for i in start .. stop:
      procs.add((i, startProcess("gpg",
        args = @["--batch", "--yes", "--quiet", "--status-fd", "2", "-d", "--", paths[i]],
        options = {poUsePath})))
    for (i, p) in procs:
      let plain = p.outputStream.readAll()
      let status = p.errorStream.readAll()
      let code = p.waitForExit()
      p.close()
      let problem = gpgVerdict(status, paths[i], code, verifySig, allowed,
                               checkPresent)
      result[i] = if problem.len > 0: ("", problem) else: (plain, "")

proc effectiveSigner*(cfg: GpgConfig): string =
  ## An empty signer means the config was built without going through
  ## `initGpgConfig`, which library callers and tests legitimately do. Treat it
  ## as the long-standing behaviour rather than as an error: a vault that
  ## worked before this dispatch existed must keep working.
  if cfg.signer.len > 0: cfg.signer
  elif cfg.usesAge: "ssh"
  else: "gpg"

proc signManifest*(cfg: GpgConfig, path: string) =
  ## gpg signs while encrypting, so it needs nothing here. age does not sign at
  ## all, which is why an age vault defaults to an ssh signer.
  case cfg.effectiveSigner
  of "ssh": sshSign(cfg, path)
  of "gpg":
    if cfg.usesAge:
      nvRaise("FATAL: " & AgeGpgSigner)
  of "none": discard
  else: nvRaise(&"FATAL: unknown signer: {cfg.signer}")

proc publishSigned*(cfg: GpgConfig, tmp, dest: string) =
  ## Move freshly encrypted `tmp` over `dest` along with its detached
  ## signature. The signature is made over `tmp` first, so a signer that
  ## fails leaves `dest` and the signature that covers it untouched; signing
  ## `dest` after the rename put new ciphertext under the old signature, or
  ## under none once ssh-keygen had removed it. The two renames are not one
  ## step: a crash between them leaves the new signature at `<dest>.sig` and
  ## the record it covers at `<dest>.tmp`; moving that file over `dest`
  ## finishes the write.
  let tmpSig = tmp & ".sig"
  try:
    signManifest(cfg, tmp)
  except CatchableError:
    for leftover in [tmp, tmpSig]:
      try: removeFile(leftover) except CatchableError: discard
    raise
  syncPath(tmp)
  if fileExists(tmpSig):
    syncPath(tmpSig)
    moveFile(tmpSig, dest & ".sig")
  moveFile(tmp, dest)
  syncParentDir(dest)

proc verifyManifest*(cfg: GpgConfig, path: string, requireSig: bool,
                     checkPresent = false) =
  ## `checkPresent` (`--allow-unsigned`) lets a missing detached signature
  ## pass and still verifies one that is there.
  if not requireSig:
    if checkPresent and cfg.effectiveSigner == "ssh" and fileExists(path & ".sig"):
      sshVerify(cfg, path)
    return
  case cfg.effectiveSigner
  of "ssh": sshVerify(cfg, path)
  of "gpg":
    # Checked inline while decrypting, which an age record has nothing for.
    if cfg.usesAge:
      nvRaise("FATAL: signature verification failed: " & AgeGpgSigner)
  of "none":
    nvRaise("FATAL: signature required but this vault is configured with " &
            "`signer = none`.\n  Pass --allow-unsigned to read it anyway.")
  else: nvRaise(&"FATAL: unknown signer: {cfg.signer}")

proc signaturesInBand*(cfg: GpgConfig): bool =
  ## Whether decrypting a blob also proves who wrote it.
  ##
  ## gpg reports GOODSIG/BADSIG on its status stream while decrypting, so the
  ## per-blob check is free. age produces no such thing, and callers that
  ## insist on GOODSIG would reject every age blob. For those vaults the
  ## equivalent guarantee is assembled differently: the manifest is signed, and
  ## it records a digest of each blob that unseal and get verify before
  ## decrypting. Skipping the in-band check is therefore not a relaxation, it
  ## is the same property established one level up.
  not cfg.usesAge

proc decryptProcess*(cfg: GpgConfig, inPath, outPath: string): Process =
  ## Spawn a decryption of inPath to outPath. Both backends decrypt as a
  ## subprocess with the same shape, which is what lets the batching in
  ## `unseal` and `status` stay backend-agnostic.
  if cfg.usesAge:
    startProcess(ageBinary(),
      args = @["-d", "-i", ageIdentityPath(cfg), "-o", outPath, "--", inPath],
      options = {poUsePath})
  else:
    startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
               "-d", "-o", outPath, "--", inPath],
      options = {poUsePath})

proc decryptStream*(cfg: GpgConfig, inPath: string): Process =
  ## Spawn a decryption of `inPath` that writes the plaintext to stdout and,
  ## for gpg, its status lines to stderr. Where the bytes land is the
  ## caller's choice, so no path is handed to the backend.
  if cfg.usesAge:
    startProcess(ageBinary(),
      args = @["-d", "-i", ageIdentityPath(cfg), "--", inPath],
      options = {poUsePath})
  else:
    startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
               "-d", "--", inPath],
      options = {poUsePath})

proc encryptFileTo*(cfg: GpgConfig, recipients: seq[string],
                    inPath, outPath: string, sign = true) =
  ## Encrypt to several recipients at once. Both backends take repeated
  ## recipient flags and wrap the payload key to each, which is what lets one
  ## key file be readable by exactly the machines a group names.
  ##
  ## `sign = false` for material every recipient must be able to read on its
  ## own. gpg exits non-zero when it cannot *verify* a signature, even though
  ## it decrypted the content perfectly well, so a signed file is unreadable to
  ## any machine that does not also hold the signer's public key. Demanding
  ## that every machine import every other machine's key in order to read is
  ## the wrong coupling, and it buys nothing here: the manifest is the trust
  ## root, it is signed, and it records the digest of every blob. A tampered
  ## key file yields a decryption failure, not a forged plaintext.
  if recipients.len == 0:
    nvRaise("FATAL: no recipients to encrypt to")
  var args: seq[string] = @[]
  if cfg.usesAge:
    for r in recipients:
      if r.len == 0 or r[0] == '-' or '\n' in r or '\r' in r or '\0' in r:
        nvRaise("FATAL: invalid recipient")
      args.add("-r")
      args.add(r)
    args.add(@["-o", outPath, "--", inPath])
    let p = startProcess(ageBinary(), args = args,
                         options = {poUsePath, poStdErrToStdOut})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: age encrypt failed (exit {code}):\n{output}")
  else:
    args.add(@["--batch", "--yes", "--quiet", "--no-options", "--no-encrypt-to",
               "--trust-model", "always"])
    if sign:
      let signer = signingKey(cfg)
      args.add(@["--local-user", signer, "--sign"])
    args.add("-e")
    for r in recipients:
      if r.len == 0 or r[0] == '-' or '\n' in r or '\r' in r or '\0' in r:
        nvRaise("FATAL: invalid recipient")
      args.add("--recipient=" & r)
    args.add(@["--set-filename", "", "-o", outPath, "--", inPath])
    let p = startProcess("gpg", args = args,
                         options = {poUsePath, poStdErrToStdOut})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: gpg encrypt failed (exit {code}):\n{output}")

proc encryptProcess*(cfg: GpgConfig, inPath, outPath: string): Process =
  if cfg.usesAge:
    startProcess(ageBinary(),
      args = @["-r", cfg.recipient, "-o", outPath, "--", inPath],
      options = {poUsePath, poStdErrToStdOut})
  else:
    let signer = signingKey(cfg)
    startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--no-options", "--no-encrypt-to",
               "--trust-model", "always",
               "--local-user", signer,
               "--sign", "-e", "--recipient=" & cfg.recipient,
               "--set-filename", "", "-o", outPath, "--", inPath],
      options = {poUsePath, poStdErrToStdOut})
