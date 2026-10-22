## Descriptor-relative file calls, and copying a child's output into a
## descriptor.
##
## A write that must stay inside a directory checked once goes through an
## open descriptor for that directory, so a later swap of a component above
## it does not redirect the write. Plaintext from gpg or age arrives on a pipe
## and is copied into a file this process created, so neither tool is handed
## a path to write.

import std/[osproc, posix, streams, sysrand]

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

proc sameFile*(a, b: Stat): bool =
  a.st_dev == b.st_dev and a.st_ino == b.st_ino

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

type Drain* = object
  ## One child whose stdout goes into `outFd` (-1 discards it) and whose
  ## stderr is kept in `err`.
  p*: Process
  outFd*: cint
  capture*: bool
  outp*: string
  err*: string
  head*: string    ## first bytes of stdout, at most two
  writeErr*: cint  ## errno of a write to `outFd` that failed, else 0
  code*: int

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
        elif jobs[i].capture:
          let at = jobs[i].outp.len
          jobs[i].outp.setLen(at + n)
          copyMem(addr jobs[i].outp[at], addr buf[0], n)
  for i in 0 .. jobs.high:
    jobs[i].code = jobs[i].p.waitForExit()
    jobs[i].p.close()

type FeedResult* = tuple[outp, err: string, code: int, writeErr: cint]

proc runWithInput*(p: Process, input: string): FeedResult =
  ## Feed `input` to `p` while draining stdout and stderr together.
  var inOpen = true
  var outOpen = true
  var errOpen = true
  var off = 0
  let inFd = p.inputHandle.cint
  template closeInput() =
    if not inOpen:
      discard
    else:
      try:
        p.inputStream.close()
      except CatchableError:
        if result.writeErr == 0:
          result.writeErr = EIO
      inOpen = false
  let inFlags = fcntl(inFd, F_GETFL, 0)
  if inFlags >= 0:
    discard fcntl(inFd, F_SETFL, inFlags or O_NONBLOCK)
  if input.len == 0:
    closeInput()
  var buf: array[65536, char]
  while inOpen or outOpen or errOpen:
    var fds: seq[TPollfd] = @[]
    var owner: seq[int] = @[]
    if inOpen:
      fds.add(TPollfd(fd: inFd, events: POLLOUT))
      owner.add(0)
    if outOpen:
      fds.add(TPollfd(fd: p.outputHandle.cint, events: POLLIN))
      owner.add(1)
    if errOpen:
      fds.add(TPollfd(fd: p.errorHandle.cint, events: POLLIN))
      owner.add(2)
    if fds.len == 0:
      break
    if poll(addr fds[0], fds.len.Tnfds, -1) < 0:
      if errno == EINTR:
        continue
      if result.writeErr == 0:
        result.writeErr = EIO
      if inOpen:
        closeInput()
      p.kill()
      break
    for k in 0 .. fds.high:
      if fds[k].revents == 0:
        continue
      case owner[k]
      of 0:
        if off >= input.len:
          closeInput()
          continue
        let take = min(input.len - off, 16384)
        let n = posix.write(fds[k].fd, unsafeAddr input[off], take)
        if n < 0:
          if errno == EINTR or errno == EAGAIN:
            continue
          if result.writeErr == 0:
            result.writeErr = errno
          closeInput()
        elif n == 0:
          if result.writeErr == 0:
            result.writeErr = EIO
          closeInput()
        else:
          off += n
          if off >= input.len:
            closeInput()
      of 1:
        let n = posix.read(fds[k].fd, addr buf[0], buf.len)
        if n < 0 and (errno == EINTR or errno == EAGAIN):
          continue
        if n <= 0:
          outOpen = false
        else:
          let at = result.outp.len
          result.outp.setLen(at + n)
          copyMem(addr result.outp[at], addr buf[0], n)
      else:
        let n = posix.read(fds[k].fd, addr buf[0], buf.len)
        if n < 0 and (errno == EINTR or errno == EAGAIN):
          continue
        if n <= 0:
          errOpen = false
        else:
          let at = result.err.len
          result.err.setLen(at + n)
          copyMem(addr result.err[at], addr buf[0], n)
  result.code = p.waitForExit()
  if off < input.len and result.writeErr == 0:
    # Child exited before consuming all input: treat the short write the same
    # as EPIPE so callers fail closed.
    result.writeErr = EPIPE
  p.close()
