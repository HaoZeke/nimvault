## nimvault -- GPG-encrypted opaque-blob vault with hidden filenames.
##
## Library root: re-exports public API modules.

import nimvault/[gpg, manifest, commands]
export gpg, manifest, commands

when isMainModule:
  import nimvault/cli
  cli.main()
