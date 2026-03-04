## Tests for nimvault/manifest: genId uniqueness, expandHome, VaultEntry.

import std/[os, sets]
import nimvault/[manifest, gpg]

block genIdUniqueness:
  ## Generate 100 IDs, verify all unique and 16 chars hex.
  var ids: HashSet[string]
  for i in 0..<100:
    let id = genId()
    doAssert id.len == 16, "genId should produce 16-char hex string"
    for c in id:
      doAssert c in {'0'..'9', 'a'..'f'}, "genId should produce lowercase hex"
    doAssert id notin ids, "genId should produce unique IDs"
    ids.incl(id)
  echo "PASS: genId uniqueness (100 IDs)"

block expandHomeTests:
  let home = getHomeDir()
  doAssert expandHome("~/foo/bar") == home / "foo/bar"
  doAssert expandHome("/absolute/path") == "/absolute/path"
  doAssert expandHome("relative/path") == "relative/path"
  echo "PASS: expandHome"

block vaultDirTest:
  doAssert vaultDir("/tmp/myrepo") == "/tmp/myrepo/.vault"
  echo "PASS: vaultDir"

block isPathSafeRootMode:
  ## Path safety checks in root-relative mode.
  let cfg = GpgConfig(recipient: "test", root: "/tmp/myrepo")
  doAssert isPathSafe(cfg, "secrets/key.txt"), "Normal relative path should be safe"
  doAssert isPathSafe(cfg, "deep/nested/file"), "Nested path should be safe"
  doAssert not isPathSafe(cfg, "../../etc/passwd"), "Traversal should be unsafe"
  doAssert not isPathSafe(cfg, "../outside"), "Parent traversal should be unsafe"
  echo "PASS: isPathSafe root mode"

block isPathSafeHomeMode:
  ## Path safety checks in home-relative mode.
  let cfg = GpgConfig(recipient: "test")
  doAssert isPathSafe(cfg, "~/Documents/secret.txt"), "Home path should be safe"
  doAssert not isPathSafe(cfg, "~/../../etc/passwd"), "Home traversal should be unsafe"
  echo "PASS: isPathSafe home mode"

echo "All manifest tests passed."
