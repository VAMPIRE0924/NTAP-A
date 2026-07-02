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

The protocol constants and shared wire helpers must have a single source of
truth in this directory. `direct_token.c` is shared by NTAP-A token issuance and
NTAP-B token validation so direct-mode auth cannot drift between endpoints.
