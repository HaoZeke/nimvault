The manifest and the blobs it vouches for are now flushed to stable storage in
the order that survives a crash. Renaming the manifest into place is atomic
against a concurrent reader, which is a different property from durability: the
rename can reach disk before the bytes it points at, leaving the trust root for
every blob present and empty. The orderings file systems actually guarantee
here are narrower than the write-temp-then-rename idiom suggests (Bornholt et
al., ASPLOS 2016, `doi:10.1145/2872362.2872406`; Chidambaram et al., SOSP 2013,
`doi:10.1145/2517349.2522726`).

`seal` now flushes each new blob before writing the manifest that records its
hash, so a crash cannot leave an entry promising bytes that never landed — which
would have surfaced later as an integrity failure on a file nobody touched.
