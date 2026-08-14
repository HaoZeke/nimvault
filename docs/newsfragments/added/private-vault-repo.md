The vault no longer has to live in the repository you are standing in. Every
command accepts `--vault DIR`, and the location also resolves from
`NIMVAULT_VAULT_REPO` or a `.nimvault` pointer file committed in the content
repository.

This exists so `.vault/` can sit in a *private* repository while the dotfiles it
protects stay public. A vault inside a public repo archives its ciphertext
permanently — anyone who clones or forks keeps a copy, and on GitHub the objects
remain fetchable through the fork network even after a history rewrite. Neither
key rotation nor `rotate --rekey` reaches that, because both act on the working
tree. Separating the repositories is worth more than any feature here.

Reading is unaffected: the manifest already stores target paths with a `~/`
prefix, so entries do not care which repository their blobs came from.

`root` is refused rather than guessed when it is set and the vault lives
elsewhere, since "relative to the repository" stops being a single answer once
there are two.

`scan` previously advertised a `--vault` flag that was parsed and then ignored;
it now does what it says.
