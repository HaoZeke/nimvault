`wrap` rules in `.vault/config` decide which recipients may open which entries,
so not every machine has to be able to read every secret:

```ini
recipient = LAPTOPKEY
wrap = ~/.ssh/**:LAPTOPKEY
wrap = **:LAPTOPKEY,BUILDBOXKEY
```

The first matching rule wins, so order is precedence. An entry matching no rule
uses `recipient`, which is why a config without `wrap` lines behaves exactly as
before.

Data keys are grouped by recipient set and each group is written to its own
`.vault/keys.<group>.gpg`, encrypted to that group alone. A machine decrypts
the group files its key opens and no others. `unseal` restores what it can
read; `check` needs no key at all, so integrity is verifiable from anywhere.
`rotate` recomputes groups, so editing the rules and rotating moves an entry's
key between group files without touching any payload.

Key files are encrypted but not signed. gpg exits non-zero when it cannot
*verify* a signature even after decrypting the content perfectly well, so a
signed key file would be unreadable on any machine that did not also hold the
signer's public key — requiring every machine to import every other machine's
key just to read. That coupling buys nothing here: the manifest remains the
trust root, it is signed, and it records the digest of every blob, so a tampered
key file causes a decryption failure rather than a forged plaintext.

Groups are only worth something when machines hold *different* keys. Sharing one
private key across machines means every machine opens every group and the split
is decoration.
