`nimvault get <path>` prints one entry's plaintext on stdout without unsealing
the vault or writing anything to disk. It performs the same path-safety and
blob-integrity checks `unseal` does, so a caller reading a single credential
gets the same guarantees as one restoring everything.
