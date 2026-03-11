# Package
version       = "0.3.0"
author        = "Rohit Goswami"
description   = "GPG-encrypted opaque-blob vault with hidden filenames"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @["nimvault"]
binDir        = "bin"

# Dependencies
requires "nim >= 2.0.0"
requires "cligen >= 1.9.0"

task test, "Run test suite":
  for f in listFiles("tests"):
    if f.endsWith(".nim"):
      exec "nim c -r --hints:off -p:src " & f
