Payloads are now encrypted under a per-file data key, and the data keys live in
one small file encrypted to the recipients (format v6).

Until now each blob was encrypted straight to the recipient. Both backends do
envelope encryption internally — GPG draws a session key per file, age a file
key — but that wrapping lives *inside* the blob, so the recipient was baked into
every payload and changing or adding one rewrote the whole vault. On a
158-entry vault, letting a second machine read meant a full re-encrypt and a
diff nobody could review.

`nimvault rotate` rewraps the data keys to whoever `.vault/config` now names and
leaves every payload untouched, so adding a machine costs one small file.
`nimvault rotate --rekey` re-encrypts every payload under a fresh data key
instead.

The two are deliberately separate. Rewrapping rotates the *wrapping* key: a
recipient that should no longer open the vault stops being able to. It does
nothing about a data key that has already leaked, because the old ciphertext is
unchanged and the old key still opens it — only `--rekey` answers that. The
distinction between cheap rewrapping and real re-encryption is the subject of
Everspaugh et al., CRYPTO 2017 (`doi:10.1007/978-3-319-63697-9_4`); updatable
encryption exists to narrow the gap (Lehmann and Tackmann, EUROCRYPT 2018,
`doi:10.1007/978-3-319-78372-7_22`).

Migration is incremental and needs no action: a v5 entry moves to v6 when its
plaintext next changes, so ordinary work drains the old format. Mixed vaults
read correctly — an entry with a data key is v6, one without is v5, and the key
file is the discriminator. `nimvault seal --force` migrates everything at once.

Data keys are distinct per entry, so a leak of one opens one, and a key whose
entry has been removed is dropped rather than kept.
