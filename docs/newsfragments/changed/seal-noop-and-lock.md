A `seal` that changes nothing no longer rewrites the manifest. The manifest is
encrypted and signed, so writing it is itself a change: without this, every
seal left one modified file and a fresh signature over identical content, and
the incremental seal above could never produce a clean `git status`.

Mutating commands (`seal`, `add`, `add-dir`, `rm`, `mv`) now take a per-vault
lock before touching the manifest. Each of them rewrites the manifest from a
copy read moments earlier, so two at once was a lost update: both read the same
entries, both wrote, and the loser's blob stayed on disk with no entry pointing
at it. The lock is an `fcntl` record under `$XDG_RUNTIME_DIR`, so the kernel
releases it even on a crash, a vault checkout gains no untracked file, and a
read-only checkout can still be locked. It excludes other nimvault processes,
not threads within one.

The manifest is now encrypted to a temporary file and renamed into place, so a
concurrent reader sees either the old manifest or the new one, never a
half-written trust root.
