`nimvault seal` now re-encrypts only the files whose plaintext changed. GPG and
age both draw a fresh session key per run, so re-sealing an untouched file still
produced a different blob: a one-file edit arrived in git as a diff touching
every blob in the vault, and the real change was invisible inside it. A file is
skipped when its plaintext hash, its blob and that blob's own hash all still
agree with the manifest, so a deleted or corrupted blob is still rebuilt.

The manifest (v5) records a seal key covering the backend, recipient, identity
and signer. Changing any of them re-encrypts everything, because unchanged
plaintext still owes a fresh blob under a new key; a v4 manifest with no
recorded key also seals in full once to establish one. `nimvault seal --force`
re-encrypts regardless.
