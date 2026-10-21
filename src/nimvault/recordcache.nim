## Plaintext cache for split entry records keyed by ciphertext digest.
##
## This cache is process-local and safe to share across read paths because a
## caller only gets cached plaintext when the on-disk ciphertext bytes still
## hash to what was verified when cached.

import std/[os, tables]
import ./gpg

var recordCache {.threadvar.}: Table[string, tuple[cipherHash, plain: string]]

proc cacheScope*(cfg: GpgConfig): string =
  ## Record plaintext is only reusable for the same decryption identity.
  ## GNUPGHOME is where gpg's secret keys live; age uses cfg.identity.
  let gpgHome = getEnv("GNUPGHOME")
  let ageIdentity = if cfg.backend == "age": cfg.identity else: ""
  cfg.backend & "\t" & gpgHome & "\t" & ageIdentity

proc recordCipherHash(path: string): string =
  ## Hash of encrypted record bytes; empty when unreadable.
  try:
    sha256sum(path)
  except CatchableError:
    ""

proc rememberRecordPlain*(scope, path, plain: string) =
  let digest = recordCipherHash(path)
  if digest.len > 0:
    recordCache[scope & "\t" & path] = (digest, plain)

proc recalledRecordPlain*(scope, path: string): string =
  ## Cached plaintext when ciphertext bytes are unchanged; empty otherwise.
  let key = scope & "\t" & path
  if not recordCache.hasKey(key):
    return ""
  let (digest, plain) = recordCache[key]
  if digest == recordCipherHash(path): plain else: ""
