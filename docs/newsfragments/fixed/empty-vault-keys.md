Emptying a vault now drops its data keys. `seal` returned early when the
manifest held no entries, before the pruning that removes key files for
entries that no longer exist — leaving a key able to open blobs while
guarding nothing, which is the case that pruning exists to prevent.
