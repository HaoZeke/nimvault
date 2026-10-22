## Vault manifest operations: entry types, load/save, ID generation.

import std/[os, strutils, strformat, sysrand, tables, sets, algorithm]
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
const RecordSetGenerationHeader* = "# vault-record-generation"

proc generationStatePath(repo: string): string =
  ## Local anti-rollback state, outside `.vault` so a vault-only writer cannot
  ## move it backwards.
  let gitDir = repo / ".git"
  if dirExists(gitDir):
    gitDir / "nimvault-generation"
  else:
    repo / ".nimvault-generation"

proc readSeenGeneration(repo: string): int64 =
  let path = generationStatePath(repo)
  if not fileExists(path):
    return 0
  let raw = readFile(path).strip()
  if raw.len == 0:
    return 0
  try:
    result = int64(parseBiggestInt(raw))
  except ValueError:
    nvRaise(&"FATAL: malformed local generation state: {path}")

proc writeSeenGeneration(repo: string, gen: int64) =
  if gen <= 0:
    return
  let path = generationStatePath(repo)
  writeFile(path, $gen & "\n")
  setFilePermissions(path, {fpUserRead, fpUserWrite})

proc enforceGenerationFloor(repo: string, gen: int64) =
  ## Reject a signed stub older than what this machine already accepted.
  if gen <= 0:
    return
  let seen = readSeenGeneration(repo)
  if gen < seen:
    nvRaise(&"FATAL: refusing manifest generation rollback: saw {gen}, " &
            &"last seen {seen} on this machine")
  if gen > seen:
    writeSeenGeneration(repo, gen)

proc nextGeneration(repo: string, currentStub: int64): int64 =
  let seen = readSeenGeneration(repo)
  (if currentStub > seen: currentStub else: seen) + 1

proc signedStubGeneration(repo: string, cfg: GpgConfig): int64 =
  ## Current signed stub generation without requiring the signed record-set
  ## rows to match disk. Mutating commands use this before they rewrite both.
  let enc = findManifest(repo, cfg)
  if enc.len == 0:
    return 0
  var plain = ""
  try:
    plain = verifyAndDecryptToString(cfg, enc,
      verifySig = cfg.effectiveSigner != "none",
      checkPresent = true)
  except CatchableError as err:
    if cfg.usesAge:
      let low = err.msg.toLowerAscii()
      if "no identity matched" in low or "no identities matched" in low:
        return readSeenGeneration(repo)
    elif gpgNoSecretKey(err.msg):
      return readSeenGeneration(repo)
    raise
  for line in plain.splitLines:
    let stripped = line.strip()
    if stripped.startsWith(RecordSetGenerationHeader):
      let raw = stripped[RecordSetGenerationHeader.len .. ^1].strip()
      try:
        return int64(parseBiggestInt(raw))
      except ValueError:
        nvRaise(&"FATAL: malformed record generation in manifest stub: {enc}")

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
  elif ".." in manifestPath.split('/'):
    # No root bounds the result, so nothing short of the raw components can
    # tell a deliberate absolute path from one that climbs out of it.
    false
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

proc isRecordCipherName(name: string): bool =
  name.endsWith(".gpg") or name.endsWith(".age")

proc hasSplitEntries*(repo: string): bool =
  let dir = entryDir(repo)
  if not dirExists(dir):
    return false
  for kind, path in walkDir(dir):
    let name = path.extractFilename
    if kind == pcLinkToFile and (isRecordCipherName(name) or
        name.endsWith(".sig")):
      nvRaise(&"FATAL: refusing symlinked record file: {path}")
    if kind == pcFile and isRecordCipherName(name):
      return true
  return false

proc entryFile*(repo: string, cfg: GpgConfig, id: string): string =
  entryDir(repo) / (id & cfg.blobExt)

proc findEntryFile*(repo: string, cfg: GpgConfig, id: string): string =
  let mine = entryFile(repo, cfg, id)
  if symlinkExists(mine):
    nvRaise(&"FATAL: refusing symlinked record file: {mine}")
  if fileExists(mine):
    assertVaultRegularFile(mine)
    return mine
  let other = entryDir(repo) / (id & (if cfg.usesAge: ".gpg" else: ".age"))
  if symlinkExists(other):
    nvRaise(&"FATAL: refusing symlinked record file: {other}")
  if fileExists(other):
    assertVaultRegularFile(other)
    return other
  return ""

proc splitRecordIds*(repo: string): HashSet[string] =
  ## Ids that have a per-entry file, including those this identity cannot
  ## open. A wrap-subset view must not treat the rest as gone.
  result = initHashSet[string]()
  let dir = entryDir(repo)
  if not dirExists(dir):
    return
  for kind, path in walkDir(dir):
    let name = path.extractFilename
    let recordNode = isRecordCipherName(name) or name.endsWith(".sig")
    if kind == pcLinkToFile and recordNode:
      nvRaise(&"FATAL: refusing symlinked record file: {path}")
    if not recordNode:
      continue
    if kind != pcFile:
      nvRaise(&"FATAL: refusing non-regular record file: {path}")
    assertVaultRegularFile(path)
    if name.endsWith(".sig"):
      continue
    result.incl(name.rsplit('.', maxsplit = 1)[0])

type RecordDigestRow = tuple[id, digest: string]

proc recordDigestRows(repo: string): seq[RecordDigestRow] =
  ## Id + digest for every record file currently in `.vault/e/`.
  let dir = entryDir(repo)
  if not dirExists(dir):
    return
  var seen = initHashSet[string]()
  for kind, path in walkDir(dir):
    let name = path.extractFilename
    let recordNode = isRecordCipherName(name) or name.endsWith(".sig")
    if kind == pcLinkToFile and recordNode:
      nvRaise(&"FATAL: refusing symlinked record file: {path}")
    if not recordNode:
      continue
    if kind != pcFile:
      nvRaise(&"FATAL: refusing non-regular record file: {path}")
    assertVaultRegularFile(path)
    if name.endsWith(".sig"):
      continue
    let id = name.rsplit('.', maxsplit = 1)[0]
    if id in seen:
      nvRaise(&"FATAL: duplicate record id on disk: {id}")
    seen.incl(id)
    let digest = sha256sumBytes(readVaultRegularFile(path))
    result.add((id, digest))
    let sig = path & ".sig"
    if fileExists(sig):
      assertVaultRegularFile(sig)
  sort(result, proc(a, b: RecordDigestRow): int = cmp(a.id, b.id))

proc dropEntryRecord*(repo: string, cfg: GpgConfig, id: string) =
  ## Remove one split record this command just deleted. Other stems stay.
  let path = findEntryFile(repo, cfg, id)
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
    # A pre-v6 entry has no data key, so its record ends in a tab.
    let stripped = line.strip(chars = Whitespace - {'\t'})
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('\t')
    if parts.len < 5:
      continue
    let kind = if parts[3] == "dir": ekDir else: ekFile
    result.entry = (parts[0], parts[1], parts[2], kind, parts[4])
    result.dek = if parts.len > 5: parts[5] else: ""
    result.ok = true
    got = true
    break
  if not got:
    result.ok = false

var recordCache {.threadvar.}: Table[string, tuple[cipherHash, plain: string]]
  ## Plaintext cache for split records, keyed by the digest of the ciphertext
  ## this process decrypted or wrote. Callers still compare that digest to the
  ## live ciphertext before trusting the cached plaintext.

proc recordCipherHash(path: string): string =
  ## Hash of the encrypted record bytes; empty when unreadable.
  try:
    sha256sum(path)
  except CatchableError:
    ""

proc rememberRecord(path, digest, plain: string) =
  if digest.len > 0:
    recordCache[path] = (digest, plain)

proc recalledRecord(path: string): string =
  ## Cached plaintext of `path` only when live ciphertext still hashes to the
  ## digest this process already decrypted; empty otherwise.
  if not recordCache.hasKey(path):
    return ""
  let (digest, plain) = recordCache[path]
  if digest == recordCipherHash(path): plain else: ""

proc loadSplitEntries*(repo: string, cfg: GpgConfig,
                       verifySig = false,
                       checkPresent = false): tuple[entries: seq[VaultEntry],
                                                    deks: DekTable,
                                                    recordDigests: Table[string, string],
                                                    unread, unparsed: int] =
  ## Union of every per-entry record this machine can open. `unparsed` counts
  ## records that opened and verified but hold no entry line.
  let dir = entryDir(repo)
  if not dirExists(dir):
    return
  # A bad or missing signature is fatal; a record this identity cannot
  # decrypt is skippable. The first is a replaced trust root, the second is
  # "not for us".
  template sigFailure(msg: string): bool =
    (verifySig or checkPresent) and ("signature verification failed" in msg or
                                     "missing signature" in msg or
                                     "signature required" in msg)
  proc noSecretKey(msg: string): bool =
    if cfg.usesAge:
      let low = msg.toLowerAscii()
      ("no identity matched" in low) or ("no identities matched" in low)
    else:
      gpgNoSecretKey(msg)
  type Snapshot = tuple[id, path, snap, snapSig, digest: string]
  var snaps: seq[Snapshot] = @[]
  var seenIds = initHashSet[string]()
  let work = privateWorkDir()
  defer:
    discardPrivate(work)
  for kind, path in walkDir(dir):
    let name = path.extractFilename
    let recordNode = isRecordCipherName(name) or name.endsWith(".sig")
    if kind == pcLinkToFile and recordNode:
      nvRaise(&"FATAL: refusing symlinked record file: {path}")
    if not recordNode:
      continue
    if kind != pcFile:
      nvRaise(&"FATAL: refusing non-regular record file: {path}")
    assertVaultRegularFile(path)
    if name.endsWith(".sig"):
      continue
    let id = name.rsplit('.', maxsplit = 1)[0]
    if id in seenIds:
      nvRaise(&"FATAL: duplicate record id on disk: {id}")
    seenIds.incl(id)
    let ext = if name.endsWith(".age"): ".age" else: ".gpg"
    let stem = $snaps.len
    let snap = work / ("record-" & stem & ext)
    let snapSig = snap & ".sig"
    let cipher = readVaultRegularFile(path)
    let digest = sha256sumBytes(cipher)
    result.recordDigests[id] = digest
    writeFile(snap, cipher)
    let sig = path & ".sig"
    if fileExists(sig):
      writeFile(snapSig, readVaultRegularFile(sig))
    snaps.add((id, path, snap, snapSig, digest))
  var seenParsedIds = initHashSet[string]()
  for s in snaps:
    var plain = ""
    var err = ""
    try:
      plain = verifyAndDecryptToString(cfg, s.snap, verifySig, checkPresent)
    except CatchableError as problem:
      err = problem.msg
      if s.snap in err:
        err = err.replace(s.snap, s.path)
      if s.snapSig in err:
        err = err.replace(s.snapSig, s.path & ".sig")
    if err.len > 0:
      if sigFailure(err):
        nvRaise(err)
      if noSecretKey(err):
        result.unread.inc
        continue
      nvRaise(err)
    rememberRecord(s.path, s.digest, plain)
    let parsed = parseEntryPlain(plain)
    if parsed.ok:
      if parsed.entry.id != s.id:
        nvRaise(&"FATAL: record id does not match filename: {s.path}")
      if parsed.entry.id in seenParsedIds:
        nvRaise(&"FATAL: duplicate record id in decrypted records: {parsed.entry.id}")
      seenParsedIds.incl(parsed.entry.id)
      result.entries.add(parsed.entry)
      if parsed.dek.len > 0:
        result.deks[parsed.entry.id] = parsed.dek
    else:
      result.unparsed.inc

proc saveEntryRecord*(repo: string, cfg: GpgConfig, e: VaultEntry, dek: string) =
  ## Write one signed encrypted record. A different id is a different path,
  ## which is why two adds merge.
  let recips = recipientsFor(cfg, e.path)
  createDir(entryDir(repo))
  let work = privateWorkDir()
  let plainPath = work / "entry.plain"
  let cipherPath = work / ("entry" & cfg.blobExt)
  let dest = entryFile(repo, cfg, e.id)
  var content = EntryHeader & "\n"
  content.add(&"{e.id}\t{e.path}\t{e.hash}\t{e.kind}\t{e.contentHash}\t{dek}\n")
  writeFile(plainPath, content)
  setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
  try:
    encryptFileTo(cfg, recips, plainPath, cipherPath, sign = not cfg.usesAge)
    let cipherHash = sha256sum(cipherPath)
    publishSigned(cfg, cipherPath, dest)
    rememberRecord(dest, cipherHash, content)
  finally:
    discardPrivate(work)

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
  if symlinkExists(path):
    nvRaise(&"FATAL: refusing symlinked record file: {path}")
  let plain = recalledRecord(path)
  let checked =
    if plain.len > 0:
      plain
    else:
      verifyAndDecryptToString(cfg, path, verifySig = cfg.effectiveSigner != "none",
                               checkPresent = true)
  let parsed = parseEntryPlain(checked)
  parsed.ok and parsed.entry == e and parsed.dek == dek

proc saveSplitEntries*(repo: string, cfg: GpgConfig, entries: seq[VaultEntry],
                       deks: DekTable, force = false) =
  ## Write the records this identity can open. Unchanged stems stay as
  ## they are on disk so a sibling add is a new path, not a rewrite.
  ## `force` is for rotate, which must rewrap even when the fields match.
  ## Unread stems stay; `dropEntryRecord` is the only remover.
  createDir(entryDir(repo))
  for e in entries:
    let dek = deks.getOrDefault(e.id)
    if not force and entryRecordUnchanged(repo, cfg, e, dek):
      continue
    saveEntryRecord(repo, cfg, e, dek)
  # Do not delete stems that are missing from `entries`. That list is
  # only what this identity could open; unread wrap-private records
  # stay until dropEntryRecord names them.

proc loadManifestMeta*(repo: string, verifySig = false,
                       cfg = GpgConfig(),
                       checkPresent = false): tuple[entries: seq[VaultEntry],
                                                    sealKey: string,
                                                    envelope: bool,
                                                    generation: int64,
                                                    unopened, unparsed: int,
                                                    deks: DekTable] =
  ## Decrypt and parse the vault manifest, with the seal key it was written
  ## under (empty for v4 and earlier, which did not record one).
  ## Returns empty seq if no manifest exists. `unparsed` counts records and
  ## manifest lines that opened but hold no entry this binary can read.
  ## Supports v1–v5 (v4 adds plaintext contentHash for fast `status`;
  ## v5 adds the `# vault-seal-key` header).
  ##
  ## `cfg` is optional so the many call sites that only read a gpg vault stay
  ## unchanged. `findManifest` still refuses to report a vault sealed by the
  ## other backend as empty, so omitting it fails loudly rather than quietly.
  ##
  ## `checkPresent` is `--allow-unsigned`: with `verifySig` off, a signature
  ## that is present must still verify and come from a configured signer.
  if hasSplitEntries(repo):
    let split = loadSplitEntries(repo, cfg, verifySig, checkPresent)
    result.entries = split.entries
    result.unopened = split.unread
    result.unparsed = split.unparsed
    result.deks = split.deks
    result.envelope = true
    var rowGeneration: int64 = 0
    var rows = initTable[string, tuple[digest: string, generation: int64]]()
    var stubUnread = false
    proc noSecretKey(msg: string): bool =
      if cfg.usesAge:
        let low = msg.toLowerAscii()
        ("no identity matched" in low) or ("no identities matched" in low)
      else:
        gpgNoSecretKey(msg)
    # Seal key still lives on the stub combined manifest when one exists.
    let encStub = findManifest(repo, cfg)
    if encStub.len > 0:
      try:
        let stub = verifyAndDecryptToString(cfg, encStub, verifySig, checkPresent)
        for line in stub.splitLines:
          let stripped = line.strip()
          if stripped.startsWith(SealKeyHeader):
            result.sealKey = stripped[SealKeyHeader.len .. ^1].strip()
            continue
          if stripped.startsWith(EnvelopeHeader):
            result.envelope = true
            continue
          if stripped.startsWith(RecordSetGenerationHeader):
            let raw = stripped[RecordSetGenerationHeader.len .. ^1].strip()
            try:
              result.generation = int64(parseBiggestInt(raw))
            except ValueError:
              nvRaise(&"FATAL: malformed record generation in manifest stub: {encStub}")
            continue
          if stripped.len == 0 or stripped.startsWith("#"):
            continue
          let parts = stripped.split('\t')
          if parts.len < 3:
            result.unparsed.inc
            continue
          let id = parts[0]
          if id in rows:
            nvRaise(&"FATAL: duplicate id in signed record set: {id}")
          var gen: int64
          try:
            gen = int64(parseBiggestInt(parts[2]))
          except ValueError:
            nvRaise(&"FATAL: malformed generation for id {id} in manifest stub")
          rows[id] = (parts[1], gen)
          if rowGeneration == 0:
            rowGeneration = gen
          elif rowGeneration != gen:
            nvRaise("FATAL: inconsistent generations inside signed record set")
      except CatchableError as err:
        let msg = err.msg.toLowerAscii()
        if "signature verification failed" in msg or
           "missing signature" in msg or
           "signature required" in msg:
          raise
        if noSecretKey(err.msg):
          stubUnread = true
        else:
          discard
    if rowGeneration > 0:
      if result.generation == 0:
        result.generation = rowGeneration
      elif result.generation != rowGeneration:
        nvRaise("FATAL: manifest stub generation does not match row generation")
    if result.generation > 0:
      enforceGenerationFloor(repo, result.generation)
    if split.recordDigests.len > 0:
      if rows.len == 0:
        if stubUnread:
          result.unopened = max(result.unopened, split.recordDigests.len)
        else:
          nvRaise("FATAL: missing signed record set in split-manifest stub")
      for id, digest in split.recordDigests:
        if rows.len == 0:
          break
        if id notin rows:
          nvRaise(&"FATAL: split record missing from signed set: {id}")
        if rows[id].digest != digest:
          nvRaise(&"FATAL: signed digest mismatch for record id {id}")
      if rows.len > 0:
        for id in rows.keys:
          if id notin split.recordDigests:
            nvRaise(&"FATAL: signed set lists record missing on disk: {id}")
    elif rows.len > 0:
      nvRaise("FATAL: signed set lists records but none are on disk")
    return
  let enc = findManifest(repo, cfg)
  if enc.len == 0:
    return (@[], "", false, 0'i64, 0, 0, initTable[string, string]())
  let plain = verifyAndDecryptToString(cfg, enc, verifySig, checkPresent)
  for line in plain.splitLines:
    let stripped = line.strip()
    if stripped.startsWith(SealKeyHeader):
      result.sealKey = stripped[SealKeyHeader.len .. ^1].strip()
      continue
    if stripped.startsWith(EnvelopeHeader):
      result.envelope = true
      continue
    if stripped.startsWith(RecordSetGenerationHeader):
      let raw = stripped[RecordSetGenerationHeader.len .. ^1].strip()
      try:
        result.generation = int64(parseBiggestInt(raw))
      except ValueError:
        nvRaise(&"FATAL: malformed record generation in manifest: {enc}")
      continue
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    let parts = stripped.split('\t')
    if parts.len < 2:
      result.unparsed.inc
    elif parts.len == 2:
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
                   cfg = GpgConfig(), checkPresent = false): seq[VaultEntry] =
  ## Entries only; see [loadManifestMeta] when the seal key matters.
  loadManifestMeta(repo, verifySig, cfg, checkPresent).entries

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
  var stubGeneration = 0'i64
  if envelope:
    content.add(&"{EnvelopeHeader} 1\n")
    # Split records are the mergeable trust root. The combined file signs the
    # complete set of record ids and record digests, plus a monotonic
    # generation this machine remembers outside `.vault`.
    let existingGeneration = signedStubGeneration(repo, cfg)
    let deks = if haveDeks: knownDeks else: loadDeks(repo, cfg)
    saveSplitEntries(repo, cfg, entries, deks)
    let rows = recordDigestRows(repo)
    stubGeneration = nextGeneration(repo, existingGeneration)
    content.add(&"{RecordSetGenerationHeader} {stubGeneration}\n")
    for row in rows:
      content.add(&"{row.id}\t{row.digest}\t{stubGeneration}\n")
  for e in entries:
    if envelope:
      break
    content.add(&"{e.id}\t{e.path}\t{e.hash}\t{e.kind}\t{e.contentHash}\n")
  writeFile(plainPath, content)
  setFilePermissions(plainPath, {fpUserRead, fpUserWrite})
  # Encrypt under the private work directory, then publish with a no-follow
  # temp in the destination directory. Writing encPath in place leaves a window
  # where it is half a file, and a reader that lands in that window sees the
  # trust root for every blob truncated.
  let tmpEnc = work / ("manifest" & cfg.blobExt)
  try:
    encryptFile(cfg, plainPath, tmpEnc)
    # Durability, which rename alone does not give: flush the bytes before the
    # rename that points at them, and the directory entry after, or a crash can
    # leave the trust root present and empty. See `syncPath`.
    # The manifest is the trust root: its hashes are what vouch for every blob,
    # so it is the one thing that has to be signed when the backend cannot.
    publishSigned(cfg, tmpEnc, encPath)
    if envelope and stubGeneration > 0:
      writeSeenGeneration(repo, stubGeneration)
  finally:
    discardPrivate(work)

proc saveManifestKeep*(repo: string, entries: seq[VaultEntry], cfg: GpgConfig,
                       envelope = false,
                       knownDeks: DekTable = initTable[string, string](),
                       haveDeks = false) =
  ## Rewrite the entry list without dropping the seal key or the envelope
  ## mark. add/rm/mv/addDir used to call `saveManifest` with the defaults
  ## and so forced the next seal to re-encrypt every blob.
  let meta = loadManifestMeta(repo, verifySig = cfg.effectiveSigner != "none",
                              cfg = cfg, checkPresent = true)
  saveManifest(repo, entries, cfg, meta.sealKey, meta.envelope or envelope,
               knownDeks = knownDeks, haveDeks = haveDeks)
