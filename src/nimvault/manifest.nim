## Vault manifest operations: entry types, load/save, ID generation.

import std/[os, strutils, strformat, sysrand, tables, sets, times, algorithm]
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
const AppendDirName* = "a"
  ## Public-key append records. Same line as `e/`, encrypted to the recipients
  ## and not signed, because the writer has no secret key. A signed `e/` record
  ## for the same id wins.
const EntryHeader* = "# vault-entry-v7"
const BlobIndexName* = "blob-index"
const BlobIndexHeader* = "# nimvault-blob-index-v1"
const DigestHeader* = "# nimvault-digests-v1"

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

proc appendDir*(repo: string): string =
  vaultDir(repo) / AppendDirName

proc dirHasCipher(dir: string): bool =
  if not dirExists(dir):
    return false
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.endsWith(".gpg") or name.endsWith(".age"):
      return true
  false

proc hasSplitEntries*(repo: string): bool =
  dirHasCipher(entryDir(repo))

proc hasAppendEntries*(repo: string): bool =
  dirHasCipher(appendDir(repo))

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

proc cipherIds(dir: string): HashSet[string] =
  ## Stems of ciphertext files in `dir`, including ones this identity cannot
  ## open. A wrap-subset view must not treat the rest as gone.
  result = initHashSet[string]()
  if not dirExists(dir):
    return
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.endsWith(".sig"):
      continue
    if not (name.endsWith(".gpg") or name.endsWith(".age")):
      continue
    result.incl(name.rsplit('.', maxsplit = 1)[0])

proc splitRecordIds*(repo: string): HashSet[string] =
  cipherIds(entryDir(repo))

proc appendRecordIds*(repo: string): HashSet[string] =
  cipherIds(appendDir(repo))

proc appendOnlyIds*(repo: string): HashSet[string] =
  ## Ids that exist only as an unsigned `.vault/a/` fragment.
  ## A signed `.vault/e/` record for the same id is the trust root.
  result = appendRecordIds(repo)
  for id in splitRecordIds(repo):
    result.excl(id)

proc dropEntryRecord*(repo: string, cfg: GpgConfig, id: string) =
  ## Remove one split record this command just deleted. Other stems stay.
  let path = findEntryFile(repo, cfg, id)
  if path.len == 0:
    return
  removeFile(path)
  let sig = path & ".sig"
  if fileExists(sig):
    removeFile(sig)

proc appendFile*(repo: string, cfg: GpgConfig, id: string): string =
  appendDir(repo) / (id & cfg.blobExt)

proc findAppendFile*(repo: string, cfg: GpgConfig, id: string): string =
  let mine = appendFile(repo, cfg, id)
  if fileExists(mine):
    return mine
  let other = appendDir(repo) / (id & (if cfg.usesAge: ".gpg" else: ".age"))
  if fileExists(other):
    return other
  return ""

proc dropAppendRecord*(repo: string, cfg: GpgConfig, id: string) =
  ## Remove one public-key fragment. A signed `e/` record has replaced it,
  ## or the entry itself is gone.
  let path = findAppendFile(repo, cfg, id)
  if path.len == 0:
    return
  removeFile(path)
  let sig = path & ".sig"
  if fileExists(sig):
    removeFile(sig)

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
    cfg.signerIdentity & "\n" & cfg.wraps.join("\n"))

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

var recordCache {.threadvar.}: Table[string, tuple[mtime: Time, plain: string]]
  ## Plaintext of the split records this process decrypted, by path, with
  ## the modification time it was read at. A record rewritten since is read
  ## again.

proc rememberRecord(path, plain: string) =
  try:
    recordCache[path] = (getLastModificationTime(path), plain)
  except OSError:
    discard

proc recalledRecord(path: string): string =
  ## The cached plaintext of `path` when the file has not moved since it
  ## was read; empty otherwise.
  if not recordCache.hasKey(path):
    return ""
  let (mtime, plain) = recordCache[path]
  try:
    if getLastModificationTime(path) == mtime: plain else: ""
  except OSError:
    ""

proc loadSplitEntries*(repo: string, cfg: GpgConfig,
                       verifySig = false): tuple[entries: seq[VaultEntry],
                                                 deks: DekTable] =
  ## Union of every per-entry record this machine can open.
  let dir = entryDir(repo)
  if not dirExists(dir):
    return
  # A bad or missing signature is fatal; a record this identity cannot
  # decrypt is skippable. The first is a replaced trust root, the second is
  # "not for us".
  template sigFailure(msg: string): bool =
    verifySig and ("signature verification failed" in msg or
                   "missing signature" in msg or
                   "signature required" in msg)
  var paths: seq[string] = @[]
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if not (name.endsWith(".gpg") or name.endsWith(".age")):
      continue
    if name.endsWith(".sig"):
      continue
    if verifySig:
      try:
        verifyManifest(cfg, path, true)
      except CatchableError:
        if sigFailure(getCurrentExceptionMsg()):
          raise
        continue
    paths.add(path)
  let plains = decryptManyToString(cfg, paths, verifySig)
  for i, path in paths:
    let (plain, err) = plains[i]
    if err.len > 0:
      if sigFailure(err):
        nvRaise(err)
      continue
    rememberRecord(path, plain)
    let parsed = parseEntryPlain(plain)
    if parsed.ok:
      result.entries.add(parsed.entry)
      if parsed.dek.len > 0:
        result.deks[parsed.entry.id] = parsed.dek

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
    discardPrivate(work)
  syncPath(tmp)
  moveFile(tmp, dest)
  syncParentDir(dest)
  signManifest(cfg, dest)
  rememberRecord(dest, content)

proc entryRecordUnchanged(repo: string, cfg: GpgConfig, e: VaultEntry,
                          dek: string): bool =
  ## The plaintext comes from what this command already decrypted when the
  ## file has not moved since; a seal loads every record and then asks this
  ## of each, and decrypting twice doubled its gpg calls.
  ## True when the on-disk record already carries this plaintext. GPG/age
  ## ciphertext is not stable, so add/seal must not rewrite that file or
  ## two machines that each add a different id clash on the shared stem.
  let path = findEntryFile(repo, cfg, e.id)
  if path.len == 0:
    return false
  try:
    let plain = recalledRecord(path)
    let parsed = parseEntryPlain(
      if plain.len > 0: plain else: decryptToString(cfg, path, false))
    parsed.ok and parsed.entry == e and parsed.dek == dek
  except CatchableError:
    false

proc saveAppendRecord*(repo: string, cfg: GpgConfig, e: VaultEntry, dek: string) =
  ## One encrypted fragment for a writer with no secret key.
  ##
  ## The combined manifest and a signed `e/` record both need a signature,
  ## and a signature needs a secret key. This file is encrypted to the same
  ## recipients as a signed record, so the path stays inside ciphertext, and
  ## it is a new path, so it does not rewrite any existing record.
  ##
  ## It is not signed. Anyone who has the recipient public keys can plant one.
  ## A bad signature on an `e/` record is still fatal. `check` against the
  ## blob-index and a previous digest list is what makes a plant visible
  ## without a key. A later `seal` or `rotate` by a holder of a secret key
  ## rewrites a changed fragment as a signed `e/` record.
  let recips = recipientsFor(cfg, e.path)
  createDir(appendDir(repo))
  let work = privateWorkDir()
  let plainPath = work / "entry.plain"
  let dest = appendFile(repo, cfg, e.id)
  var content = EntryHeader & "\n"
  content.add("# vault-append\n")
  content.add(&"{e.id}\t{e.path}\t{e.hash}\t{e.kind}\t{e.contentHash}\t{dek}\n")
  writeFile(plainPath, content)
  setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
  let tmp = dest & ".tmp"
  try:
    encryptFileTo(cfg, recips, plainPath, tmp, sign = false)
  finally:
    if dirExists(work):
      removeDir(work)
  syncPath(tmp)
  moveFile(tmp, dest)
  syncParentDir(dest)

proc appendRecordUnchanged(repo: string, cfg: GpgConfig, e: VaultEntry,
                           dek: string): bool =
  ## True when `.vault/a/<id>` already carries this plaintext. Same reason
  ## as `entryRecordUnchanged`: ciphertext is not stable, so a seal that
  ## did not change the entry must not rewrite the fragment.
  let path = findAppendFile(repo, cfg, e.id)
  if path.len == 0:
    return false
  try:
    let cached = recalledRecord(path)
    let plain = if cached.len > 0: cached
                else: decryptToString(cfg, path, false)
    if cached.len == 0:
      rememberRecord(path, plain)
    let parsed = parseEntryPlain(plain)
    parsed.ok and parsed.entry == e and parsed.dek == dek
  except CatchableError:
    false

proc saveSplitEntries*(repo: string, cfg: GpgConfig, entries: seq[VaultEntry],
                       deks: DekTable, force = false) =
  ## Write the records this identity can open. Unchanged stems stay as
  ## they are on disk so a sibling add is a new path, not a rewrite.
  ## `force` is for rotate, which must rewrap even when the fields match.
  ## Unread stems stay; `dropEntryRecord` is the only remover.
  ##
  ## An unchanged fragment stays in `.vault/a/`. `adopt` signs it into
  ## `.vault/e/`. A fragment whose path matches a signed record stays
  ## unsigned, so a plant is not signed over an entry the vault already
  ## trusts. `force` (rotate) signs every other openable fragment.
  createDir(entryDir(repo))
  let unsigned = appendOnlyIds(repo)
  var signedPaths = initHashSet[string]()
  for e in entries:
    if e.id notin unsigned:
      signedPaths.incl(normalizedPath(resolvePath(cfg, e.path)))
  for e in entries:
    if e.id in unsigned and
       normalizedPath(resolvePath(cfg, e.path)) in signedPaths:
      continue
    let dek = deks.getOrDefault(e.id)
    if not force and entryRecordUnchanged(repo, cfg, e, dek):
      dropAppendRecord(repo, cfg, e.id)
      continue
    if not force and appendRecordUnchanged(repo, cfg, e, dek):
      continue
    saveEntryRecord(repo, cfg, e, dek)
    dropAppendRecord(repo, cfg, e.id)
  # Do not delete stems that are missing from `entries`. That list is
  # only what this identity could open; unread wrap-private records
  # stay until dropEntryRecord names them.

proc loadAppendEntries(repo: string, cfg: GpgConfig): seq[VaultEntry] =
  ## Public-key fragments this identity can decrypt. No signature is required:
  ## the writer did not have a key. A fragment this identity cannot decrypt
  ## is skipped. These files are not in `.vault/e/`, so a missing signature
  ## here does not weaken the check on signed records.
  let dir = appendDir(repo)
  if not dirExists(dir):
    return
  var paths: seq[string] = @[]
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    if name.endsWith(".sig"):
      continue
    if not (name.endsWith(".gpg") or name.endsWith(".age")):
      continue
    paths.add(path)
  let plains = decryptManyToString(cfg, paths, false)
  for i, path in paths:
    let (plain, err) = plains[i]
    if err.len > 0:
      continue
    rememberRecord(path, plain)
    let parsed = parseEntryPlain(plain)
    if parsed.ok:
      result.add(parsed.entry)

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
  let sealed = hasSplitEntries(repo) or hasAppendEntries(repo)
  if publicKeyOnly(cfg) and (sealed or findManifest(repo, cfg).len > 0):
    nvRaise("FATAL: no secret key; cannot read sealed entries.\n" &
            "  A public-key writer can add and seal new entries, and check " &
            "without a key.", 3)
  if sealed:
    let split = loadSplitEntries(repo, cfg, verifySig)
    result.entries = split.entries
    result.envelope = true
    var seen = initHashSet[string]()
    for e in result.entries:
      seen.incl(e.id)
    # Signed records win. An append fragment is only the copy a public-key
    # writer could produce.
    for e in loadAppendEntries(repo, cfg):
      if e.id notin seen:
        result.entries.add(e)
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
                   sealKey = "", envelope = false,
                   knownDeks: DekTable = initTable[string, string](),
                   haveDeks = false) =
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
    let deks = if haveDeks: knownDeks else: loadDeks(repo, cfg)
    saveSplitEntries(repo, cfg, entries, deks)
    if existing.sealKey == sealKey and findManifest(repo, cfg).len > 0 and
       existing.envelope:
      discardPrivate(work)
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
    discardPrivate(work)
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

proc blobIndexPath(repo: string): string =
  vaultDir(repo) / BlobIndexName

proc blobIndexExists*(repo: string): bool =
  fileExists(blobIndexPath(repo))

proc readBlobIndex*(repo: string): Table[string, string] =
  ## Payload id to ciphertext sha256. No paths. Empty when the file is absent.
  let path = blobIndexPath(repo)
  if not fileExists(path):
    return
  for line in lines(path):
    let s = line.strip()
    if s.len == 0 or s.startsWith("#"):
      continue
    let sp = s.rfind(' ')
    if sp <= 0:
      continue
    result[s[0 ..< sp]] = s[sp + 1 .. ^1]

proc writeBlobIndex(repo: string, rows: Table[string, string]) =
  ensureVaultDir(repo)
  var ids: seq[string] = @[]
  for id in rows.keys:
    ids.add(id)
  ids.sort()
  var content = BlobIndexHeader & "\n"
  for id in ids:
    content.add(id & " " & rows[id] & "\n")
  let dest = blobIndexPath(repo)
  let tmp = dest & ".tmp"
  writeFile(tmp, content)
  setFilePermissions(tmp, {fpUserRead, fpUserWrite})
  syncPath(tmp)
  moveFile(tmp, dest)
  syncParentDir(dest)

proc noteBlob*(repo, id, hash: string) =
  ## Record one payload hash and leave every other id alone. A writer who
  ## cannot read those entries must not drop their lines.
  if id.len == 0 or hash.len == 0:
    return
  var rows = readBlobIndex(repo)
  if rows.getOrDefault(id) == hash:
    return
  rows[id] = hash
  writeBlobIndex(repo, rows)

proc forgetBlob*(repo, id: string) =
  var rows = readBlobIndex(repo)
  if id notin rows:
    return
  rows.del(id)
  writeBlobIndex(repo, rows)

proc payloadBlobHashes*(repo: string): Table[string, string] =
  ## Top-level `.vault/<16 hex>.gpg` files. Key files are `keys.<id>.gpg`
  ## and are not payloads.
  let dir = vaultDir(repo)
  if not dirExists(dir):
    return
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let name = path.extractFilename
    let ext = if name.endsWith(".gpg"): ".gpg"
              elif name.endsWith(".age"): ".age"
              else: ""
    if ext.len == 0:
      continue
    let stem = name[0 ..< name.len - ext.len]
    if stem.len != 16:
      continue
    var hexOk = true
    for c in stem:
      if c notin {'0'..'9', 'a'..'f'}:
        hexOk = false
        break
    if hexOk:
      result[stem] = sha256sum(path)

proc readDigestFile*(path: string): Table[string, string] =
  if not fileExists(path):
    return
  for line in lines(path):
    let s = line.strip()
    if s.len == 0 or s.startsWith("#"):
      continue
    let sp = s.rfind(' ')
    if sp <= 0:
      continue
    result[s[0 ..< sp]] = s[sp + 1 .. ^1]

proc writeDigestFile*(path: string, rows: seq[(string, string)]) =
  ## Snapshot of ciphertext hashes. This is what is on disk, not a claim
  ## that it matches a previous snapshot.
  var content = DigestHeader & "\n"
  for (rel, hash) in rows:
    content.add(rel & " " & hash & "\n")
  let tmp = path & ".tmp"
  writeFile(tmp, content)
  setFilePermissions(tmp, {fpUserRead, fpUserWrite})
  syncPath(tmp)
  moveFile(tmp, path)

proc vaultCipherDigests*(repo: string): seq[(string, string)] =
  ## Every file under `.vault/` except plaintext `config` and temp files.
  ## Relative paths only: an entry's name is not in this list.
  let dir = vaultDir(repo)
  if not dirExists(dir):
    return
  for path in walkDirRec(dir, yieldFilter = {pcFile}):
    let rel = relativePath(path, dir)
    if rel == "config" or rel.endsWith(".tmp"):
      continue
    result.add((rel, sha256sum(path)))
  result.sort(proc (a, b: (string, string)): int = cmp(a[0], b[0]))
