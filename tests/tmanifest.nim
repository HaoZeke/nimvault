## Tests for nimvault/manifest: genId uniqueness, expandHome, VaultEntry.

import std/[os, sets]
import nimvault/manifest

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

echo "All manifest tests passed."
