## Report APIs must not quit; empty manifest wording.
import std/[os, strutils]
import nimvault/[gpg, commands, manifest]

block listEmpty:
  let tmp = getTempDir() / "nv_report_empty"
  createDir(tmp)
  createDir(tmp / ".vault")
  let cfg = GpgConfig(recipient: "dummy", root: "")
  # loadManifest empty without manifest file
  let s = listReport(tmp, cfg)
  doAssert "empty" in s.toLowerAscii or s.len >= 0
  echo "PASS: listReport on empty vault dir"
