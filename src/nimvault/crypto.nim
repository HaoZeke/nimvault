## Backend dispatch: route encryption and decryption to gpg or age.
##
## Kept in its own module so neither backend has to know the other exists, and
## so the choice is made in exactly one place rather than at each call site.

import std/[os, strformat]
from ./gpg import GpgConfig, nvRaise, gpgEncrypt, gpgDecrypt, gpgDecryptToString
from ./age import ageEncrypt, ageDecrypt, ageDecryptToString, sshSign, sshVerify

proc usesAge*(cfg: GpgConfig): bool =
  cfg.backend == "age"

proc blobExt*(cfg: GpgConfig): string =
  ## Blobs and the manifest carry the extension of the primitive that made
  ## them. Giving both backends the same name would make a vault that cannot be
  ## read look like a vault that is empty, which is the worst of the available
  ## failure modes: silent and reassuring.
  if cfg.usesAge: ".age" else: ".gpg"

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
