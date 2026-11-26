## Metadata locks: package version is one number, and the docs workflow
## must not grant write on a pull_request job.
##
## These are the two tickets that are true of the public tree without
## needing GPG: nimvault-w24f (pixi.toml still 0.3.0) and nimvault-qscx
## (ci_docs.yml contents: write on the PR-triggered job).

import std/[os, strutils, strformat]

const Root = currentSourcePath().parentDir.parentDir

proc fieldAfter(src, key: string): string =
  ## First quoted string after `key` on its own assignment line.
  for line in src.splitLines:
    let s = line.strip()
    if s.startsWith(key):
      let q1 = s.find('"')
      if q1 < 0: continue
      let q2 = s.find('"', q1 + 1)
      if q2 < 0: continue
      return s[q1 + 1 ..< q2]
  return ""

block versionsAgree:
  let nimble = fieldAfter(readFile(Root / "nimvault.nimble"), "version")
  let pixi = fieldAfter(readFile(Root / "pixi.toml"), "version")
  let cli = fieldAfter(readFile(Root / "src" / "nimvault" / "version.nim"),
                       "const Version")
  doAssert nimble.len > 0, "nimvault.nimble has no version"
  doAssert cli == nimble, &"cli Version {cli} != nimble {nimble}"
  doAssert pixi == nimble,
    &"pixi.toml version {pixi} != nimble {nimble} (nimvault-w24f)"
  let lib = readFile(Root / "src" / "libnimvault.nim")
  doAssert "0.4.2-lib" notin lib, "libnimvault still reports 0.4.2-lib"
  doAssert "cstring(Version)" in lib or nimble in lib,
    "libnimvault must share the CLI version"
  echo "PASS: package versions agree (", nimble, ")"

block docsWorkflowDoesNotWriteOnPullRequest:
  ## The build job runs on pull_request and must not hold contents: write.
  ## Deploy is a separate job gated on push.
  let y = readFile(Root / ".github" / "workflows" / "ci_docs.yml")
  doAssert "pull_request:" in y
  doAssert "deploy_docs:" in y,
    "deploy must be its own job, not a step on the PR-triggered build"
  let deployAt = y.find("deploy_docs:")
  doAssert y.find("if: github.event_name == 'push'", deployAt) >= 0,
    "deploy_docs must be gated on push"
  let buildAt = y.find("build_docs:")
  doAssert buildAt >= 0
  let buildChunk = y[buildAt ..< deployAt]
  doAssert "contents: write" notin buildChunk,
    "build_docs must not hold contents: write (nimvault-qscx)"
  doAssert "peaceiris/actions-gh-pages" notin buildChunk,
    "gh-pages deploy must not run in the PR-triggered job"
  echo "PASS: docs workflow isolates write to a push-only deploy job"

block releaseWorkflowAssets:
  ## Asset names already published stay, and the next tag adds the two
  ## missing binaries plus one checksum file. Linux stays a static musl
  ## build that does not load libpcre.
  let y = readFile(Root / ".github" / "workflows" / "ci_release.yml")
  for name in ["nimvault-linux-amd64", "nimvault-linux-arm64",
               "nimvault-macos-arm64", "nimvault-macos-amd64",
               "nimvault-windows-amd64"]:
    doAssert name in y, "release workflow dropped " & name
  doAssert "musl-gcc" in y
  doAssert "--passL:-static" in y
  doAssert "libpcre" in y
  doAssert "SHA256SUMS" in y
  doAssert "nimvault.exe" in y
  doAssert "macos-15-intel" in y
  doAssert "windows-latest" in y
  doAssert "os: macos-13" notin y
  echo "PASS: release workflow keeps current assets and adds macos amd64, windows, checksums"

echo "All metadata tests passed."
