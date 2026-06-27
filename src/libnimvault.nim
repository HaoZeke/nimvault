## C ABI for in-process use (nimvault-mcp). Call nv_free on returned success strings.
## Build: nimble buildLib  → lib/libnimvault.so

import std/[os, strutils]
import nimvault/[gpg, commands]

var gLastError: string

proc nv_version(): cstring {.exportc, dynlib, cdecl.} =
  cstring("0.4.2-lib")

proc nv_free(p: pointer) {.exportc, dynlib, cdecl.} =
  if p != nil:
    dealloc(p)

proc dupC(s: string): cstring =
  let n = s.len
  let p = alloc0(n + 1)
  if n > 0:
    copyMem(p, s.cstring, n)
  result = cast[cstring](p)

proc nv_last_error(): cstring {.exportc, dynlib, cdecl.} =
  if gLastError.len == 0:
    return nil
  result = gLastError.cstring

proc setupRepo(repoC, recipientC: cstring): (string, GpgConfig) =
  gLastError = ""
  nvQuiet = true
  if repoC == nil or repoC[0] == '\0':
    nvRaise("repo path is required")
  let repo = $repoC
  if not dirExists(repo):
    nvRaise("repo path does not exist: " & repo)
  let recipient = if recipientC == nil: "" else: $recipientC
  let cfg = initGpgConfig(recipient, repo)
  (repo, cfg)

template exportOp(body: untyped): cstring =
  gLastError = ""
  nvQuiet = true
  try:
    let text = body
    dupC(text)
  except NimvaultError as e:
    gLastError = e.msg
    nil
  except CatchableError as e:
    gLastError = e.msg
    nil

proc nv_list(repo: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    commands.listReport(r, cfg)

proc nv_status(repo: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    commands.statusReport(r, cfg)

proc nv_seal(repo: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    commands.sealReport(r, cfg)

proc nv_unseal(repo: cstring, recipient: cstring, allowUnsigned: cint): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    commands.unsealReport(r, cfg, allowUnsigned != 0)

proc nv_add(repo: cstring, path: cstring, recipient: cstring, noGitignore: cint): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    if path == nil or path[0] == '\0':
      nvRaise("path is required")
    commands.addReport(r, $path, cfg, noGitignore != 0)

proc nv_add_dir(repo: cstring, path: cstring, recipient: cstring, noGitignore: cint): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    if path == nil or path[0] == '\0':
      nvRaise("path is required")
    commands.addDirReport(r, $path, cfg, noGitignore != 0)

proc nv_remove(repo: cstring, path: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    if path == nil or path[0] == '\0':
      nvRaise("path is required")
    commands.removeReport(r, $path, cfg)

proc nv_mv(repo: cstring, oldPath: cstring, newPath: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    if oldPath == nil or newPath == nil:
      nvRaise("old_path and new_path are required")
    commands.moveReport(r, $oldPath, $newPath, cfg)

proc nv_scan(repo: cstring, path: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  exportOp:
    let (r, cfg) = setupRepo(repo, recipient)
    let target = if path == nil or path[0] == '\0': r else: $path
    commands.scanReport(r, target, cfg)
