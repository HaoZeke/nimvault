`nimvault gc` removes blobs in `.vault/` that no manifest entry points at, with
`--dry-run` to list them first.

Orphans are reachable when a mutation is interrupted between writing a blob and
writing the manifest that names it — the vault lock makes that rarer but does
not remove the case. An orphan is not only clutter: it is a readable copy of a
secret that nothing tracks, so nothing will ever rotate or remove it.

The manifest, the data-key files, and every blob a live entry names are left
alone.
