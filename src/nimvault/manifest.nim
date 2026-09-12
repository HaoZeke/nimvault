## Vault manifest operations: entry types, load/save, ID generation.

import std/[os, strutils, strformat, sysrand, tables]
import ./gpg
import ./crypto
import ./dek

type
  EntryKind* = enum
    ekFile = "file",    ## Regular file entry
    ekDir = "dir"      ## Directory entry (for future use)
  ## hash = SHA-256 of ciphertext blob; contentHash = SHA-256 of plaintext (optional, v4+).
  VaultEntry* = tuple[id, path, hash: string, kind: EntryKind, contentHash: string]

const SealKeyHeader* = "# vault-seal-key"
  ## Comment header, so every older reader skips it as a comment.
const EnvelopeHeader* = "# vault-envelope"
  ## Set when this vault has per-file data keys. `check` uses it to refuse
  ## a vault whose blobs still match but whose key file is gone.
const EntryDirName* = "e"
  ## Per-entry records. Two machines that add different files write different
  ## paths under here, so git can merge them. The combined manifest cannot.
const EntryHeader* = "# vault-entry-v7"

proc genId*(): string =
  ## 16-char random hex via cryptographic randomness.
  var buf: array[8, byte]
  doAssert urandom(buf)
  for b in buf:
    result.add(b.toHex(2).toLowerAscii())

proc expandHome*(p: string): string =
  ## Expand ~ to $HOME in path strings.
  if p.startsWith("~/"):
    result = getHomeDir() / p[2..^1]
  else:
    result = p

proc resolvePath*(cfg: GpgConfig, path: string): string =
  ## Resolve a manifest path to an absolute filesystem path.
  ## When cfg.root is set, paths are relative to root.
  ## Otherwise, ~/... paths are expanded via expandHome.
  if cfg.root.len > 0:
    cfg.root / path
  else:
    expandHome(path)

proc storePath*(cfg: GpgConfig, absPath: string, repo: string): string =
  ## Convert an absolute path to the stored manifest format.
  ## When cfg.root is set, stores relative to root.
  ## Otherwise, stores with ~/ prefix if under HOME.
  if cfg.root.len > 0:
    relativePath(absPath, cfg.root)
  elif absPath.startsWith(getHomeDir()):
    "~/" & relativePath(absPath, getHomeDir())
  else:
    absPath

proc isPathSafe*(cfg: GpgConfig, manifestPath: string): bool =
  ## Validate that a manifest path resolves within expected boundaries.
  ## Returns false for directory traversal attempts (e.g. ../../etc/passwd).
  let resolved = normalizedPath(resolvePath(cfg, manifestPath))
  if cfg.root.len > 0:
    let root = normalizedPath(cfg.root)
    resolved == root or resolved.startsWith(root & "/")
  elif manifestPath.startsWith("~/"):
    let home = normalizedPath(getHomeDir()).strip(leading = false, trailing = true, chars = {'/'})
    resolved.startsWith(home & "/")
  else:
    true  # absolute paths: user explicitly provided, their responsibility

proc vaultDir*(repo: string): string =
  ## Path to the .vault directory within a repo.
  repo / ".vault"

proc entryDir*(repo: string): string =
  vaultDir(repo) / EntryDirName

proc hasSplitEntries*(repo: string): bool =
  let dir = entryDir(repo)
  if not dirExists(dir):
    return false
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.endsWith(".gpg") or name.endsWith(".age"):
      return true
  return false

proc entryFile*(repo: string, cfg: GpgConfig, id: string): string =
  entryDir(repo) / (id & cfg.blobExt)

proc findEntryFile*(repo: string, cfg: GpgConfig, id: string): string =
  let mine = entryFile(repo, cfg, id)
  if fileExists(mine):
    return mine
  let other = entryDir(repo) / (id & (if cfg.usesAge: ".gpg" else: ".age"))
  if fileExists(other):
    return other
  return ""

proc sealKey*(cfg: GpgConfig): string =
  ## Fingerprint of everything that decides what a blob is encrypted to.
  ##
  ## `seal` may only skip a file whose plaintext is unchanged; that is sound
  ## for content, and wrong the moment the recipient, backend or signer moves,
  ## because then unchanged plaintext still owes a fresh blob under the new
  ## key. Recording this alongside the entries turns a key rotation into a
  ## full re-seal instead of a vault half-sealed to a key that is gone.
  sha256sumBytes(
    cfg.backend & "\n" & cfg.recipient & "\n" & cfg.identity & "\n" &
    cfg.signer & "\n" & cfg.signKey & "\n" & cfg.allowedSigners & "\n" &
    cfg.signerIdentity)

proc parseEntryPlain(plain: string): tuple[ok: bool, entry: VaultEntry, dek: string] =
  var got = false
  for line in plain.splitLines:
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('\t')
    if parts.len < 6:
      continue
    let kind = if parts[3] == "dir": ekDir else: ekFile
    result.entry = (parts[0], parts[1], parts[2], kind, parts[4])
    result.dek = parts[5]
    result.ok = true
    got = true
    break
  if not got:
    result.ok = false

proc loadSplitEntries*(repo: string, cfg: GpgConfig,
                       verifySig = false): tuple[entries: seq[VaultEntry],
                                                 deks: DekTable] =
  ## Union of every per-entry record this machine can open.
  let dir = entryDir(repo)
  if not dirExists(dir):
    return
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if not (name.endsWith(".gpg") or name.endsWith(".age")):
      continue
    if name.endsWith(".sig"):
      continue
    try:
      if verifySig:
        verifyManifest(cfg, path, true)
      let plain = decryptToString(cfg, path, verifySig)
      let parsed = parseEntryPlain(plain)
      if parsed.ok:
        result.entries.add(parsed.entry)
        if parsed.dek.len > 0:
          result.deks[parsed.entry.id] = parsed.dek
    except CatchableError:
      discard

proc saveEntryRecord*(repo: string, cfg: GpgConfig, e: VaultEntry, dek: string) =
  ## Write one signed encrypted record. A different id is a different path,
  ## which is why two adds merge.
  let recips = recipientsFor(cfg, e.path)
  createDir(entryDir(repo))
  let work = privateWorkDir()
  let plainPath = work / "entry.plain"
  let dest = entryFile(repo, cfg, e.id)
  var content = EntryHeader & "\n"
  content.add(&"{e.id}\t{e.path}\t{e.hash}\t{e.kind}\t{e.contentHash}\t{dek}\n")
  writeFile(plainPath, content)
  setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
  let tmp = dest & ".tmp"
  try:
    encryptFileTo(cfg, recips, plainPath, tmp, sign = not cfg.usesAge)
  finally:
    if dirExists(work):
      removeDir(work)
  syncPath(tmp)
  moveFile(tmp, dest)
  syncParentDir(dest)
  signManifest(cfg, dest)

proc saveSplitEntries*(repo: string, cfg: GpgConfig, entries: seq[VaultEntry],
                       deks: DekTable) =
  ## Persist the live set as one file per id. Records that are gone are
  ## removed so a deleted entry does not linger with its data key.
  createDir(entryDir(repo))
  var live = initTable[string, bool]()
  for e in entries:
    live[e.id] = true
    saveEntryRecord(repo, cfg, e, deks.getOrDefault(e.id))
  for kind, path in walkDir(entryDir(repo)):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.endsWith(".sig"):
      continue
    let stem = name.rsplit('.', maxsplit = 1)[0]
    if stem notin live:
      removeFile(path)
      let sig = path & ".sig"
      if fileExists(sig):
        removeFile(sig)

proc loadManifestMeta*(repo: string, verifySig = false,
                       cfg = GpgConfig()): tuple[entries: seq[VaultEntry],
                                                 sealKey: string,
                                                 envelope: bool] =
  ## Decrypt and parse the vault manifest, with the seal key it was written
  ## under (empty for v4 and earlier, which did not record one).
  ## Returns empty seq if no manifest exists.
  ## Supports v1–v5 (v4 adds plaintext contentHash for fast `status`;
  ## v5 adds the `# vault-seal-key` header).
  ##
  ## `cfg` is optional so the many call sites that only read a gpg vault stay
  ## unchanged. `findManifest` still refuses to report a vault sealed by the
  ## other backend as empty, so omitting it fails loudly rather than quietly.
  if hasSplitEntries(repo):
    let split = loadSplitEntries(repo, cfg, verifySig)
    result.entries = split.entries
    result.envelope = true
    # Seal key still lives on the stub combined manifest when one exists.
    let encStub = findManifest(repo, cfg)
    if encStub.len > 0:
      try:
        if verifySig:
          verifyManifest(cfg, encStub, true)
        let stub = decryptToString(cfg, encStub, verifySig)
        for line in stub.splitLines:
          let stripped = line.strip()
          if stripped.startsWith(SealKeyHeader):
            result.sealKey = stripped[SealKeyHeader.len .. ^1].strip()
          if stripped.startsWith(EnvelopeHeader):
            result.envelope = true
      except CatchableError:
        discard
    return
  let enc = findManifest(repo, cfg)
  if enc.len == 0:
    return (@[], "", false)
  verifyManifest(cfg, enc, verifySig)
  let plain = decryptToString(cfg, enc, verifySig)
  for line in plain.splitLines:
    let stripped = line.strip()
    if stripped.startsWith(SealKeyHeader):
      result.sealKey = stripped[SealKeyHeader.len .. ^1].strip()
      continue
    if stripped.startsWith(EnvelopeHeader):
      result.envelope = true
      continue
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('\t')
    if parts.len == 2:
      # v1: id\tpath
      result.entries.add((parts[0], parts[1], "", ekFile, ""))
    elif parts.len == 3:
      # v2: id\tpath\thash
      result.entries.add((parts[0], parts[1], parts[2], ekFile, ""))
    elif parts.len == 4:
      # v3: id\tpath\thash\tkind
      let kind = if parts[3] == "dir": ekDir else: ekFile
      result.entries.add((parts[0], parts[1], parts[2], kind, ""))
    elif parts.len >= 5:
      # v4: id\tpath\thash\tkind\tcontentHash
      let kind = if parts[3] == "dir": ekDir else: ekFile
      result.entries.add((parts[0], parts[1], parts[2], kind, parts[4]))

proc loadManifest*(repo: string, verifySig = false,
                   cfg = GpgConfig()): seq[VaultEntry] =
  ## Entries only; see [loadManifestMeta] when the seal key matters.
  loadManifestMeta(repo, verifySig, cfg).entries

proc saveManifest*(repo: string, entries: seq[VaultEntry], cfg: GpgConfig,
                   sealKey = "", envelope = false) =
  ## Serialize entries (v4: blob hash, kind, plaintext content hash) and encrypt.
  ## A non-empty `sealKey` records what the blobs are encrypted to (v5), which
  ## is what lets a later `seal` skip unchanged files without going stale
  ## across a recipient change.
  ensureVaultDir(repo)
  let work = privateWorkDir()
  let plainPath = work / "manifest.plain"
  let encPath = manifestPath(repo, cfg)
  var content = "# vault-manifest-v" & (if sealKey.len > 0: "5" else: "4") & "\n"
  if sealKey.len > 0:
    content.add(&"{SealKeyHeader} {sealKey}\n")
  if envelope:
    content.add(&"{EnvelopeHeader} 1\n")
  if envelope:
    # Split records are the mergeable trust root. The combined file is a
    # stub: seal-key plus envelope mark, no rows. Rewriting it on every add
    # would recreate the last-writer-wins hole, so the stub is only written
    # when it is missing or the seal key changed.
    let existing = loadManifestMeta(repo, cfg = cfg)
    let deks = loadDeks(repo, cfg)
    saveSplitEntries(repo, cfg, entries, deks)
    if existing.sealKey == sealKey and findManifest(repo, cfg).len > 0 and
       existing.envelope:
      if dirExists(work):
        removeDir(work)
      return
    # Fall through and write a rowless stub so old readers see an explicit
    # empty combined manifest rather than a missing one.
  for e in entries:
    if envelope:
      break
    content.add(&"{e.id}\t{e.path}\t{e.hash}\t{e.kind}\t{e.contentHash}\n")
  writeFile(plainPath, content)
  setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
  # Encrypt beside the real manifest and rename over it. Writing encPath in
  # place leaves a window where it is half a file, and a reader that lands in
  # that window sees the trust root for every blob truncated. Rename within one
  # directory is atomic, so a reader sees either the old manifest or the new.
  let tmpEnc = encPath & ".tmp"
  try:
    encryptFile(cfg, plainPath, tmpEnc)
  finally:
    if dirExists(work):
      removeDir(work)
  # Durability, which rename alone does not give: flush the bytes before the
  # rename that points at them, and the directory entry after, or a crash can
  # leave the trust root present and empty. See `syncPath`.
  syncPath(tmpEnc)
  moveFile(tmpEnc, encPath)
  syncParentDir(encPath)
  # The manifest is the trust root: its hashes are what vouch for every blob,
  # so it is the one thing that has to be signed when the backend cannot.
  signManifest(cfg, encPath)

proc saveManifestKeep*(repo: string, entries: seq[VaultEntry], cfg: GpgConfig,
                       envelope = false) =
  ## Rewrite the entry list without dropping the seal key or the envelope
  ## mark. add/rm/mv/addDir used to call `saveManifest` with the defaults
  ## and so forced the next seal to re-encrypt every blob.
  let meta = loadManifestMeta(repo, cfg = cfg)
  saveManifest(repo, entries, cfg, meta.sealKey, meta.envelope or envelope)
