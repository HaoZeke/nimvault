## Descriptor-relative file calls, and copying a child's output into a
## descriptor.
##
## A write that must stay inside a directory checked once goes through an
## open descriptor for that directory, so a later swap of a component above
## it does not redirect the write. Plaintext from gpg or age arrives on a pipe
## and is copied into a file this process created, so neither tool is handed
## a path to write.
##
## Windows has no openat. The same calls go through NtCreateFile relative to
## a directory handle, which is the handle the CRT descriptor stands for, and
## a final reparse point is refused instead of followed.

import std/[osproc, posix, sysrand]

type Drain* = object
  ## One child whose stdout goes into `outFd` (-1 discards it) and whose
  ## stderr is kept in `err`.
  p*: Process
  outFd*: cint
  err*: string
  head*: string    ## first bytes of stdout, at most two
  writeErr*: cint  ## errno of a write to `outFd` that failed, else 0
  code*: int

proc writeAll*(fd: cint, data: pointer, len: int): cint =
  ## 0 when every byte landed, else the errno of the write that failed.
  var off = 0
  while off < len:
    let w = posix.write(fd, cast[pointer](cast[int](data) + off), len - off)
    if w < 0:
      if errno == EINTR:
        continue
      return errno
    if w == 0:
      return EIO
    off += w
  0

when defined(windows):
  import std/[os, strutils]

  {.passL: "-lntdll -ladvapi32".}

  const
    ONoFollow* = 0x40000000.cint
    ODirectory* = 0x20000000.cint
    AtSymlinkNoFollow* = 0x10000000.cint
    fileReadData = 0x0001'u32
    fileWriteData = 0x0002'u32
    fileAppendData = 0x0004'u32
    fileReadEa = 0x0008'u32
    fileWriteEa = 0x0010'u32
    fileExecute = 0x0020'u32
    fileReadAttr = 0x0080'u32
    fileWriteAttr = 0x0100'u32
    deleteAccess = 0x00010000'u32
    readControl = 0x00020000'u32
    synchronize = 0x00100000'u32
    dirAccess = synchronize or deleteAccess or readControl or fileReadData or
                fileWriteData or fileAppendData or fileExecute or fileReadAttr or
                fileWriteAttr
    fileAccess = synchronize or deleteAccess or readControl or fileReadData or
                 fileWriteData or fileAppendData or fileReadEa or fileWriteEa or
                 fileReadAttr or fileWriteAttr
    shareAll = 0x00000007'u32
    attrNormal = 0x00000080'u32
    dispOpen = 1'u32
    dispCreate = 2'u32
    optDir = 0x00000001'u32
    optSync = 0x00000020'u32
    optNonDir = 0x00000040'u32
    optBackup = 0x00004000'u32
    optReparse = 0x00200000'u32
    statusNotADir = 0xC0000103'i32
    reparseAttr = 0x00000400'u32
    dirAttr = 0x00000010'u32

  {.emit: """/*INCLUDESECTION*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <aclapi.h>

static void nv_nt_errno(NTSTATUS st) {
  switch ((ULONG)st) {
  case 0xC0000034u: case 0xC000003Au: errno = ENOENT; break;
  case 0xC0000035u: errno = EEXIST; break;
  case 0xC0000103u: errno = ENOTDIR; break;
  case 0xC00000BAu: errno = EISDIR; break;
  case 0xC0000022u: case 0xC0000043u: errno = EACCES; break;
  case 0xC00000D4u: errno = EXDEV; break;
  case 0xC0000106u: errno = ENAMETOOLONG; break;
  case 0x8000002Du: errno = ELOOP; break;
  default: errno = EIO; break;
  }
}

static PSECURITY_DESCRIPTOR nv_owner_sd(void) {
  static PSECURITY_DESCRIPTOR sd = NULL;
  static int init = 0;
  if (!init) {
    init = 1;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;OICI;FA;;;CU)", SDDL_REVISION_1, &sd, NULL))
      sd = NULL;
  }
  return sd;
}

static int nv_harden(HANDLE h) {
  PSECURITY_DESCRIPTOR sd = nv_owner_sd();
  BOOL present = FALSE, defaulted = FALSE;
  PACL dacl = NULL;
  DWORD rc;
  if (!sd || !h || h == INVALID_HANDLE_VALUE) return 0;
  if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl)
    return 0;
  rc = SetSecurityInfo(h, SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
    NULL, NULL, dacl, NULL);
  return rc == ERROR_SUCCESS;
}

static int nv_harden_path(const wchar_t *path) {
  PSECURITY_DESCRIPTOR sd = nv_owner_sd();
  BOOL present = FALSE, defaulted = FALSE;
  PACL dacl = NULL;
  DWORD rc;
  if (!sd || !path) return 0;
  if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl)
    return 0;
  rc = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
    NULL, NULL, dacl, NULL);
  return rc == ERROR_SUCCESS;
}

static int nv_info(HANDLE h, DWORD *attr, ULONGLONG *size,
                   DWORD *vol, DWORD *hi, DWORD *lo) {
  BY_HANDLE_FILE_INFORMATION info;
  memset(&info, 0, sizeof(info));
  if (!h || h == INVALID_HANDLE_VALUE) return 0;
  if (!GetFileInformationByHandle(h, &info)) return 0;
  if (attr) *attr = info.dwFileAttributes;
  if (size) *size = ((ULONGLONG)info.nFileSizeHigh << 32) | info.nFileSizeLow;
  if (vol) *vol = info.dwVolumeSerialNumber;
  if (hi) *hi = info.nFileIndexHigh;
  if (lo) *lo = info.nFileIndexLow;
  return 1;
}

static void nv_delete_handle(HANDLE h) {
  FILE_DISPOSITION_INFORMATION di;
  IO_STATUS_BLOCK io;
  memset(&io, 0, sizeof(io));
  di.DoDeleteFile = TRUE;
  NtSetInformationFile(h, &io, &di, sizeof(di), FileDispositionInformation);
}
""".}

  proc setErrno(e: cint) =
    {.emit: "errno = `e`;".}

  proc utf16z(s: string): seq[uint16] =
    ## NUL-terminated UTF-16. The returned seq owns the buffer.
    let src = if s.len == 0: cstring("") else: s.cstring
    var need: int32
    {.emit: "`need` = (NI32)MultiByteToWideChar(65001, 0, `src`, -1, NULL, 0);".}
    if need <= 0:
      return @[0'u16]
    result.setLen(need.int)
    let dst = addr result[0]
    {.emit: "MultiByteToWideChar(65001, 0, `src`, -1, (wchar_t *)`dst`, (int)`need`);".}

  proc widePtr(buf: var seq[uint16]): pointer =
    if buf.len == 0:
      buf = @[0'u16]
    cast[pointer](addr buf[0])

  proc ntErrno(st: int32) =
    {.emit: "nv_nt_errno((NTSTATUS)`st`);".}

  proc osf(fd: cint): int {.importc: "_get_osfhandle", header: "<io.h>".}
  proc openOsf(h: int, flags: cint): cint {.importc: "_open_osfhandle", header: "<io.h>".}
  proc closeHandle(h: int): int32 {.importc: "CloseHandle", header: "<windows.h>", sideEffect.}
  proc commitFd*(fd: cint): cint {.importc: "_commit", header: "<io.h>", sideEffect.}
  proc seek64(fd: cint, off: int64, origin: cint): int64 {.importc: "_lseeki64", header: "<io.h>".}

  proc ntCreate(root: int, name: pointer, access, attr, share, disp, opts: uint32,
                sd: pointer): tuple[handle: int, status: int32] =
    var handle = 0
    var status: int32 = 0
    {.emit: """
      HANDLE hnd = NULL;
      UNICODE_STRING us;
      const wchar_t *w = (const wchar_t *)`name`;
      size_t nchars = 0;
      NTSTATUS st = (NTSTATUS)0xC0000106;
      while (w && w[nchars] != 0) nchars++;
      if (w && nchars > 0 && nchars <= 32767) {
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK io;
        us.Length = (USHORT)(nchars * sizeof(wchar_t));
        us.MaximumLength = (USHORT)((nchars + 1) * sizeof(wchar_t));
        us.Buffer = (PWSTR)w;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE,
          (HANDLE)(intptr_t)`root`, (PSECURITY_DESCRIPTOR)`sd`);
        memset(&io, 0, sizeof(io));
        st = NtCreateFile(&hnd, (ACCESS_MASK)`access`, &oa, &io, NULL,
          (ULONG)`attr`, (ULONG)`share`, (ULONG)`disp`, (ULONG)`opts`, NULL, 0);
      }
      `handle` = (NI)(intptr_t)hnd;
      `status` = (NI32)st;
    """.}
    (handle, status)

  proc wrapHandle(h: int): cint =
    if h == 0 or h == -1:
      return -1
    result = openOsf(h, 0x8000 or 0x0002)
    if result < 0:
      discard closeHandle(h)

  proc fileAttr(h: int): uint32 =
    var attr: uint32 = 0
    var ok: cint
    {.emit: """
      DWORD a = 0;
      `ok` = nv_info((HANDLE)(intptr_t)`h`, &a, NULL, NULL, NULL, NULL);
      `attr` = a;
    """.}
    if ok == 0: 0'u32 else: attr

  proc isReparse(h: int): bool =
    (fileAttr(h) and reparseAttr) != 0

  proc harden(h: int): bool =
    var ok: cint
    {.emit: "`ok` = nv_harden((HANDLE)(intptr_t)`h`);".}
    ok != 0

  proc deleteHandle(h: int) =
    {.emit: "nv_delete_handle((HANDLE)(intptr_t)`h`);".}

  proc componentOk(path: cstring): bool =
    if path.isNil or path[0] == '\0': return false
    let s = $path
    if s == "." or s == ".." or s.len > 255: return false
    for c in s:
      if c == '/' or c == '\\': return false
    true

  proc toNt(path: string): string =
    var n = absolutePath(path).replace('/', '\\')
    if n.startsWith("\\\\?\\"):
      n = n[4 .. ^1]
      if n.startsWith("UNC\\"):
        return "\\??\\UNC\\" & n[4 .. ^1]
      return "\\??\\" & n
    if n.len >= 2 and n[1] == ':':
      return "\\??\\" & n
    if n.startsWith("\\\\"):
      return "\\??\\UNC\\" & n[2 .. ^1]
    ""

  proc volumeNt(path: string): string =
    let nt = toNt(path)
    if nt.startsWith("\\??\\UNC\\"):
      let rest = nt[8 .. ^1]
      let s1 = rest.find('\\')
      if s1 < 0: return ""
      let s2 = rest.find('\\', s1 + 1)
      if s2 < 0: return nt
      return nt[0 ..< 8 + s2]
    if nt.len >= 6 and nt[5] == ':':
      # `\??\X:` is the drive. The root directory is `\??\X:\`, and a path
      # that already has the separator must not gain a second one.
      if nt.len >= 7 and nt[6] == '\\':
        return nt[0 .. 6]
      return nt[0 .. 5] & "\\"
    ""

  proc leadingVolumeParts*(path: string): int =
    ## Components of `path` that `openVolumeRoot` already opened.
    let n = normalizedPath(path)
    if n.len >= 2 and n[1] == ':':
      return 1
    if n.startsWith("\\\\") or n.startsWith("//"):
      return 2
    0

  proc openAbsolute(nt: string, directory, nofollow, creating: bool): cint =
    if nt.len == 0:
      setErrno(ENOENT)
      return -1
    var w = utf16z(nt)
    let raw = widePtr(w)
    var opts = optSync or optBackup
    var access = if directory: dirAccess else: fileAccess
    var disp = dispOpen
    if directory:
      opts = opts or optDir
    else:
      opts = opts or optNonDir
    if nofollow:
      opts = opts or optReparse
    if creating:
      disp = dispCreate
      opts = optSync or (if directory: optDir else: optNonDir)
    let (h, st) = ntCreate(0, raw, access, attrNormal, shareAll, disp, opts, nil)
    if st < 0:
      ntErrno(st)
      return -1
    if nofollow and isReparse(h):
      discard closeHandle(h)
      setErrno(ELOOP)
      return -1
    if creating and not harden(h):
      deleteHandle(h)
      discard closeHandle(h)
      setErrno(EIO)
      return -1
    result = wrapHandle(h)
    if result < 0:
      setErrno(EIO)

  proc openVolumeRoot*(path: string): cint =
    ## The drive or UNC share that contains `path`, as a directory handle.
    openAbsolute(volumeNt(path), directory = true, nofollow = false,
                 creating = false)

  proc openNoFollowWrite*(path: string): cint =
    ## Open an existing file for overwrite. A symlink is not followed.
    openAbsolute(toNt(path), directory = false, nofollow = true, creating = false)

  proc openRelative(dirFd: cint, path: cstring, flags: cint): cint =
    if not componentOk(path):
      setErrno(EINVAL)
      return -1
    let root = if dirFd < 0: 0 else: osf(dirFd)
    if dirFd >= 0 and (root == 0 or root == -1):
      setErrno(EBADF)
      return -1
    var w = utf16z($path)
    let raw = widePtr(w)
    let directory = (flags and ODirectory) != 0
    let creating = (flags and posix.O_CREAT) != 0
    var opts = optSync or optBackup
    let access = if directory: dirAccess else: fileAccess
    var disp = dispOpen
    if creating and directory:
      disp = dispCreate
      opts = optSync or optDir
    elif directory:
      opts = opts or optDir or optReparse
    elif creating:
      disp = dispCreate
      opts = optSync or optNonDir
    else:
      opts = opts or optNonDir or optReparse
    let (h, st) = ntCreate(root, raw, access, attrNormal, shareAll, disp, opts, nil)
    if st < 0:
      if directory and not creating and st == statusNotADir:
        let (h2, st2) = ntCreate(root, raw, fileAccess, attrNormal, shareAll,
                                 dispOpen, optSync or optBackup or optNonDir or optReparse, nil)
        if st2 < 0:
          ntErrno(st2)
          return -1
        let reparse = isReparse(h2)
        discard closeHandle(h2)
        setErrno(if reparse: ELOOP else: ENOTDIR)
        return -1
      ntErrno(st)
      return -1
    if (directory or not creating) and isReparse(h):
      discard closeHandle(h)
      setErrno(ELOOP)
      return -1
    if creating and not harden(h):
      deleteHandle(h)
      discard closeHandle(h)
      setErrno(EIO)
      return -1
    result = wrapHandle(h)
    if result < 0:
      setErrno(EIO)

  proc openAt*(dirFd: cint, path: cstring, flags: cint): cint =
    openRelative(dirFd, path, flags)

  proc openAt*(dirFd: cint, path: cstring, flags: cint, mode: Mode): cint =
    discard mode
    openRelative(dirFd, path, flags)

  proc mkdirAt*(dirFd: cint, path: cstring, mode: Mode): cint =
    discard mode
    let fd = openRelative(dirFd, path, ODirectory or posix.O_CREAT or ONoFollow)
    if fd < 0:
      return -1
    discard posix.close(fd)
    0

  proc renameAt*(oldDirFd: cint, oldPath: cstring, newDirFd: cint,
                 newPath: cstring): cint =
    if not componentOk(oldPath) or not componentOk(newPath):
      setErrno(EINVAL)
      return -1
    let src = openRelative(oldDirFd, oldPath, ONoFollow)
    if src < 0:
      return -1
    let srcH = osf(src)
    let dstH = osf(newDirFd)
    if srcH == -1 or srcH == 0 or dstH == -1 or dstH == 0:
      discard posix.close(src)
      setErrno(EBADF)
      return -1
    var w = utf16z($newPath)
    let raw = widePtr(w)
    var st: int32 = 0
    {.emit: """
      const wchar_t *wn = (const wchar_t *)`raw`;
      size_t nchars = 0;
      while (wn && wn[nchars] != 0) nchars++;
      size_t bytes = nchars * sizeof(WCHAR);
      FILE_RENAME_INFORMATION *ri = (FILE_RENAME_INFORMATION *)calloc(
        1, sizeof(FILE_RENAME_INFORMATION) + bytes);
      IO_STATUS_BLOCK io;
      NTSTATUS rst = (NTSTATUS)0xC0000001;
      if (ri && nchars > 0) {
        ri->ReplaceIfExists = TRUE;
        ri->RootDirectory = (HANDLE)(intptr_t)`dstH`;
        ri->FileNameLength = (ULONG)bytes;
        memcpy(ri->FileName, wn, bytes);
        memset(&io, 0, sizeof(io));
        rst = NtSetInformationFile((HANDLE)(intptr_t)`srcH`, &io, ri,
          (ULONG)(sizeof(FILE_RENAME_INFORMATION) + bytes), FileRenameInformation);
      }
      free(ri);
      `st` = (NI32)rst;
    """.}
    discard posix.close(src)
    if st < 0:
      ntErrno(st)
      return -1
    0

  proc unlinkAt*(dirFd: cint, path: cstring, flags: cint): cint =
    discard flags
    let fd = openRelative(dirFd, path, ONoFollow)
    if fd < 0:
      return -1
    let h = osf(fd)
    if h == 0 or h == -1:
      discard posix.close(fd)
      setErrno(EBADF)
      return -1
    deleteHandle(h)
    discard posix.close(fd)
    0

  proc replacePath*(src, dest: string): cint =
    ## Replace `dest` with `src`. A different volume sets EXDEV. The source
    ## is opened by its own path, so a same-named file in the destination
    ## directory is not what gets renamed.
    let parent = normalizedPath(absolutePath(dest.parentDir))
    if parent.len == 0:
      setErrno(ENOENT)
      return -1
    let name = dest.extractFilename
    if not componentOk(name.cstring):
      setErrno(EINVAL)
      return -1
    var dirFd = openVolumeRoot(parent)
    if dirFd < 0:
      return -1
    var skip = leadingVolumeParts(parent)
    for part in parent.split({'\\', '/'}):
      if part.len == 0 or part == ".":
        continue
      if part == "..":
        discard posix.close(dirFd)
        setErrno(EINVAL)
        return -1
      if skip > 0:
        dec skip
        continue
      let next = openAt(dirFd, part.cstring, ODirectory or ONoFollow)
      if next < 0:
        discard posix.close(dirFd)
        return -1
      discard posix.close(dirFd)
      dirFd = next
    let srcNt = toNt(src)
    var w = utf16z(srcNt)
    let raw = widePtr(w)
    let (h, st) = ntCreate(0, raw, fileAccess, attrNormal, shareAll, dispOpen,
                           optSync or optBackup or optNonDir or optReparse, nil)
    if st < 0:
      discard posix.close(dirFd)
      ntErrno(st)
      return -1
    let dstH = osf(dirFd)
    var wn = utf16z(name)
    let rawN = widePtr(wn)
    var rst: int32 = 0
    {.emit: """
      const wchar_t *wname = (const wchar_t *)`rawN`;
      size_t nchars = 0;
      while (wname && wname[nchars] != 0) nchars++;
      size_t bytes = nchars * sizeof(WCHAR);
      FILE_RENAME_INFORMATION *ri = (FILE_RENAME_INFORMATION *)calloc(
        1, sizeof(FILE_RENAME_INFORMATION) + bytes);
      IO_STATUS_BLOCK io;
      NTSTATUS stn = (NTSTATUS)0xC0000001;
      if (ri && nchars > 0) {
        ri->ReplaceIfExists = TRUE;
        ri->RootDirectory = (HANDLE)(intptr_t)`dstH`;
        ri->FileNameLength = (ULONG)bytes;
        memcpy(ri->FileName, wname, bytes);
        memset(&io, 0, sizeof(io));
        stn = NtSetInformationFile((HANDLE)(intptr_t)`h`, &io, ri,
          (ULONG)(sizeof(FILE_RENAME_INFORMATION) + bytes), FileRenameInformation);
      }
      free(ri);
      `rst` = (NI32)stn;
    """.}
    discard closeHandle(h)
    discard posix.close(dirFd)
    if rst < 0:
      ntErrno(rst)
      return -1
    0

  proc ownerOnlyFd*(fd: cint): bool =
    if fd < 0: return false
    let h = osf(fd)
    if h == 0 or h == -1: return false
    harden(h)

  proc ownerOnlyPath*(path: string): bool =
    var w = utf16z(absolutePath(path))
    let raw = widePtr(w)
    var ok: cint
    {.emit: "`ok` = nv_harden_path((const wchar_t *)`raw`);".}
    ok != 0

  proc sameOpenFile*(a, b: cint): bool =
    if a < 0 or b < 0: return false
    let ha = osf(a)
    let hb = osf(b)
    if ha == 0 or ha == -1 or hb == 0 or hb == -1: return false
    var av, ah, al, bv, bh, bl: uint32
    var ok: cint
    {.emit: """
      DWORD av=0, ah=0, al=0, bv=0, bh=0, bl=0;
      int ia = nv_info((HANDLE)(intptr_t)`ha`, NULL, NULL, &av, &ah, &al);
      int ib = nv_info((HANDLE)(intptr_t)`hb`, NULL, NULL, &bv, &bh, &bl);
      `ok` = (ia && ib && av == bv && ah == bh && al == bl) ? 1 : 0;
    """.}
    discard av
    discard ah
    discard al
    discard bv
    discard bh
    discard bl
    ok != 0

  proc heldName*(dirFd, fd: cint, name: cstring): bool =
    let other = openAt(dirFd, name, ONoFollow)
    if other < 0: return false
    result = sameOpenFile(fd, other)
    discard posix.close(other)

  proc overwriteFd*(fd: cint) =
    if fd < 0: return
    let h = osf(fd)
    if h == 0 or h == -1: return
    var attr: uint32
    var size: int64
    var ok: cint
    {.emit: """
      DWORD a = 0;
      ULONGLONG sz = 0;
      `ok` = nv_info((HANDLE)(intptr_t)`h`, &a, &sz, NULL, NULL, NULL);
      `attr` = a;
      `size` = (NI64)sz;
    """.}
    if ok == 0: return
    if (attr and reparseAttr) != 0 or (attr and dirAttr) != 0: return
    if seek64(fd, 0, 0) < 0: return
    var left = size
    var buf: array[8192, byte]
    while left > 0:
      let n = min(left, buf.len.int64).int
      if not urandom(buf):
        zeroMem(addr buf[0], buf.len)
      if writeAll(fd, addr buf[0], n) != 0:
        break
      left -= n
    discard commitFd(fd)

  proc pipeAvail(h: int, avail: var int): bool =
    if h == 0 or h == -1:
      avail = 0
      return false
    var ok: cint
    var n: int32
    {.emit: """
      DWORD a = 0;
      if (!PeekNamedPipe((HANDLE)(intptr_t)`h`, NULL, 0, NULL, &a, NULL)) {
        `ok` = 0;
        `n` = 0;
      } else {
        `ok` = 1;
        `n` = (NI32)a;
      }
    """.}
    avail = n.int
    ok != 0

  proc readPipe(h: int, buf: pointer, cap: int): int =
    var got: int32
    var ok: cint
    {.emit: """
      DWORD g = 0;
      if (!ReadFile((HANDLE)(intptr_t)`h`, `buf`, (DWORD)`cap`, &g, NULL)) {
        `ok` = 0;
        `got` = 0;
      } else {
        `ok` = 1;
        `got` = (NI32)g;
      }
    """.}
    if ok == 0: -1 else: got.int

  proc sleepMs(ms: uint32) =
    {.emit: "Sleep((DWORD)`ms`);".}

  proc handleOf(p: Process, which: int): int =
    let h = if which == 0: p.outputHandle else: p.errorHandle
    cast[int](h)

  proc drain*(jobs: var openArray[Drain]) =
    ## Read every child's stdout and stderr to the end, then reap it. A full
    ## pipe must be emptied while the child is still running, or it never
    ## exits. Windows pipes are not pollable, so this peeks each one.
    var open = newSeq[array[2, bool]](jobs.len)
    for i in 0 .. jobs.high:
      open[i] = [handleOf(jobs[i].p, 0) != 0, handleOf(jobs[i].p, 1) != 0]
    var buf: array[65536, char]
    while true:
      var any = false
      var progress = false
      for i in 0 .. jobs.high:
        for which in 0 .. 1:
          if not open[i][which]: continue
          any = true
          let h = handleOf(jobs[i].p, which)
          var avail = 0
          if not pipeAvail(h, avail):
            open[i][which] = false
            continue
          if avail <= 0 and jobs[i].p.peekExitCode != -1:
            # The child may have written and exited between the peek and the
            # exit check. Peek once more before deciding the pipe is done.
            if not pipeAvail(h, avail):
              open[i][which] = false
              continue
          if avail <= 0:
            if jobs[i].p.peekExitCode != -1:
              open[i][which] = false
            continue
          progress = true
          let n = readPipe(h, addr buf[0], min(avail, buf.len))
          if n <= 0:
            open[i][which] = false
            continue
          if which == 1:
            let at = jobs[i].err.len
            jobs[i].err.setLen(at + n)
            copyMem(addr jobs[i].err[at], addr buf[0], n)
          else:
            var j = 0
            while jobs[i].head.len < 2 and j < n:
              jobs[i].head.add(buf[j])
              inc j
            if jobs[i].outFd >= 0 and jobs[i].writeErr == 0:
              jobs[i].writeErr = writeAll(jobs[i].outFd, addr buf[0], n)
      if not any: break
      if not progress:
        sleepMs(10)
    for i in 0 .. jobs.high:
      jobs[i].code = jobs[i].p.waitForExit()
      jobs[i].p.close()

else:
  var
    ONoFollow* {.importc: "O_NOFOLLOW", header: "<fcntl.h>".}: cint
      ## Refuse a symlink in the final component instead of following it.
    ODirectory* {.importc: "O_DIRECTORY", header: "<fcntl.h>".}: cint
    AtSymlinkNoFollow* {.importc: "AT_SYMLINK_NOFOLLOW", header: "<fcntl.h>".}: cint

  proc openAt*(dirFd: cint, path: cstring, flags: cint): cint
    {.importc: "openat", header: "<fcntl.h>", varargs, sideEffect.}
    ## Pass a `Mode` after `flags` when `flags` holds `O_CREAT`.
  proc mkdirAt*(dirFd: cint, path: cstring, mode: Mode): cint
    {.importc: "mkdirat", header: "<sys/stat.h>", sideEffect.}
  proc renameAt*(oldDirFd: cint, oldPath: cstring, newDirFd: cint,
                 newPath: cstring): cint
    {.importc: "renameat", header: "<stdio.h>", sideEffect.}
  proc unlinkAt*(dirFd: cint, path: cstring, flags: cint): cint
    {.importc: "unlinkat", header: "<unistd.h>", sideEffect.}
  proc fstatAt*(dirFd: cint, path: cstring, st: var Stat, flags: cint): cint
    {.importc: "fstatat", header: "<sys/stat.h>", sideEffect.}
  proc cRename(src, dest: cstring): cint {.importc: "rename", header: "<stdio.h>".}

  proc replacePath*(src, dest: string): cint =
    cRename(src.cstring, dest.cstring)

  proc sameFile*(a, b: Stat): bool =
    a.st_dev == b.st_dev and a.st_ino == b.st_ino

  proc overwriteFd*(fd: cint) =
    ## Write random bytes over a regular file through `fd`, then flush. Best
    ## effort: a filesystem that keeps old blocks can still recover them.
    var st: Stat
    if fstat(fd, st) != 0 or not S_ISREG(st.st_mode):
      return
    if lseek(fd, 0, SEEK_SET) < 0:
      return
    var left = st.st_size.int
    var buf: array[8192, byte]
    while left > 0:
      let n = min(left, buf.len)
      if not urandom(buf):
        zeroMem(addr buf[0], buf.len)
      if writeAll(fd, addr buf[0], n) != 0:
        break
      left -= n
    discard fsync(fd)

  proc drain*(jobs: var openArray[Drain]) =
    ## Read every child's stdout and stderr to the end, then reap it. Both
    ## streams are read together across all children: a child waiting to write
    ## to a full pipe never exits, whichever pipe it is.
    var open = newSeq[array[2, bool]](jobs.len)
    for i in 0 .. jobs.high:
      open[i] = [true, true]
    var buf: array[65536, char]
    while true:
      var fds: seq[TPollfd] = @[]
      var owner: seq[(int, int)] = @[]
      for i in 0 .. jobs.high:
        if open[i][0]:
          fds.add(TPollfd(fd: jobs[i].p.outputHandle.cint, events: POLLIN))
          owner.add((i, 0))
        if open[i][1]:
          fds.add(TPollfd(fd: jobs[i].p.errorHandle.cint, events: POLLIN))
          owner.add((i, 1))
      if fds.len == 0:
        break
      if poll(addr fds[0], fds.len.Tnfds, -1) < 0:
        if errno == EINTR:
          continue
        for i in 0 .. jobs.high:
          if open[i][0] or open[i][1]:
            jobs[i].p.kill()
            if jobs[i].writeErr == 0:
              jobs[i].writeErr = EIO
        break
      for k in 0 .. fds.high:
        if fds[k].revents == 0:
          continue
        let (i, which) = owner[k]
        let n = posix.read(fds[k].fd, addr buf[0], buf.len)
        if n < 0 and (errno == EINTR or errno == EAGAIN):
          continue
        if n <= 0:
          open[i][which] = false
        elif which == 1:
          let at = jobs[i].err.len
          jobs[i].err.setLen(at + n)
          copyMem(addr jobs[i].err[at], addr buf[0], n)
        else:
          var j = 0
          while jobs[i].head.len < 2 and j < n:
            jobs[i].head.add(buf[j])
            inc j
          if jobs[i].outFd >= 0 and jobs[i].writeErr == 0:
            jobs[i].writeErr = writeAll(jobs[i].outFd, addr buf[0], n)
    for i in 0 .. jobs.high:
      jobs[i].code = jobs[i].p.waitForExit()
      jobs[i].p.close()
