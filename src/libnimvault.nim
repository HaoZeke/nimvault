## C ABI for in-process use (nimvault-mcp). Call nv_free on returned strings.
##
## Build: nimble buildLib  (produces lib/libnimvault.so)

import std/[os, strutils]
import nimvault/[gpg, commands]

var gLastError: string

proc nv_version(): cstring {.exportc, dynlib, cdecl.} =
  ## Static version string (do not free).
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
  ## Last error message (do not free; valid until next call).
  if gLastError.len == 0:
    return nil
  result = gLastError.cstring

proc runReport(repoC, recipientC: cstring, kind: string): cstring {.cdecl.} =
  gLastError = ""
  try:
    if repoC == nil or repoC[0] == '\0':
      gLastError = "repo path is required"
      return nil
    let repo = $repoC
    if not dirExists(repo):
      gLastError = "repo path does not exist: " & repo
      return nil
    let recipient = if recipientC == nil: "" else: $recipientC
    let cfg = initGpgConfig(recipient, repo)
    let report = case kind
      of "list": commands.listReport(repo, cfg)
      of "status": commands.statusReport(repo, cfg)
      else:
        gLastError = "unknown op"
        return nil
    return dupC(report)
  except CatchableError as e:
    gLastError = e.msg
    return nil

proc nv_list(repo: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  ## List vault entries. Caller must nv_free result. NULL on error (see nv_last_error).
  runReport(repo, recipient, "list")

proc nv_status(repo: cstring, recipient: cstring): cstring {.exportc, dynlib, cdecl.} =
  ## Status report (no ANSI). Caller must nv_free result.
  runReport(repo, recipient, "status")
