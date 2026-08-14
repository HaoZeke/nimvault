## Backend dispatch: route encryption and decryption to gpg or age.
##
## Kept in its own module so neither backend has to know the other exists, and
## so the choice is made in exactly one place rather than at each call site.

import std/[os, osproc, streams, strformat, posix]
from ./gpg import GpgConfig, nvRaise, gpgEncrypt, gpgDecrypt, gpgDecryptToString
from ./age import ageEncrypt, ageDecrypt, ageDecryptToString, sshSign,
                  sshVerify, ageBinary, ageIdentityPath

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
  else: gpgDecrypt(inPath, outPath, verifySig)

proc decryptToString*(cfg: GpgConfig, inPath: string, verifySig = false): string =
  if cfg.usesAge: ageDecryptToString(cfg, inPath)
  else: gpgDecryptToString(inPath, verifySig)

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
  of "none", "gpg": discard
  else: nvRaise(&"FATAL: unknown signer: {cfg.signer}")

proc verifyManifest*(cfg: GpgConfig, path: string, requireSig: bool) =
  if not requireSig:
    return
  case cfg.effectiveSigner
  of "ssh": sshVerify(cfg, path)
  of "gpg": discard  ## checked inline while decrypting
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
      args = @["-d", "-i", ageIdentityPath(cfg), "-o", outPath, inPath],
      options = {poUsePath})
  else:
    startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--status-fd", "2",
               "-d", "-o", outPath, inPath],
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
      args.add("-r")
      args.add(r)
    args.add(@["-o", outPath, inPath])
    let p = startProcess(ageBinary(), args = args,
                         options = {poUsePath, poStdErrToStdOut})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if code != 0:
      nvRaise(&"FATAL: age encrypt failed (exit {code}):\n{output}")
  else:
    args.add(@["--batch", "--yes", "--quiet", "--trust-model", "always"])
    if sign:
      args.add("--sign")
    args.add("-e")
    for r in recipients:
      args.add("-r")
      args.add(r)
    args.add(@["--set-filename", "", "-o", outPath, inPath])
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
      args = @["-r", cfg.recipient, "-o", outPath, inPath],
      options = {poUsePath, poStdErrToStdOut})
  else:
    startProcess("gpg",
      args = @["--batch", "--yes", "--quiet", "--trust-model", "always",
               "--sign", "-e", "-r", cfg.recipient,
               "--set-filename", "", "-o", outPath, inPath],
      options = {poUsePath, poStdErrToStdOut})
