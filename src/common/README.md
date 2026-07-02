# src/common

Shared C code for all NTAP binaries.

Phase 0 starts here:

```text
proto.h
proto.c
log.c
hash.c
buffer.c
time.c
config.c if shared parsing stays common
```

The protocol constants must have a single source of truth in this directory.

