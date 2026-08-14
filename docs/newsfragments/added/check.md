`nimvault check` verifies every blob against the hash the manifest records for
it, without decrypting anything or needing key material, and exits non-zero when
anything is inconsistent — so a pre-push hook or a continuous-integration job
can gate on it.

`status` answers a different question: it compares the *plaintext* on this
machine against the manifest's `contentHash`, so it says nothing about whether
the blobs still match. A blob committed without the manifest that vouches for it
therefore looks healthy in `status` right up until an `unseal` on another
machine, where the plaintext is gone and the failure is unrecoverable rather
than inconvenient. `check` closes that gap; the two commands are complementary
and neither replaces the other.

The manifest is a signed list of per-blob digests, which is a one-level Merkle
construction (Merkle, CRYPTO 1987, `doi:10.1007/3-540-48184-2_32`): checking
each leaf against it detects a drifted blob and needs no key.
