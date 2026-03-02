# Package
version       = "0.1.0"
author        = "Rohit Goswami"
description   = "GPG-encrypted opaque-blob vault with hidden filenames"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @["nimvault"]
binDir        = "bin"

# Dependencies
requires "nim >= 2.0.0"
