`nimvault unseal` now accepts paths, restoring only the entries named instead
of the whole vault. A directory restores everything beneath it, and a selector
matching nothing raises rather than reporting success for zero work. Bare
`unseal` is unchanged.
