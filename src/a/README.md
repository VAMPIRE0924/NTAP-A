# src/a

NTAP-A public control server.

Current implemented scope:

```text
config.c
db_sqlite.c
main.c
node_server.c
api_server.c
AUTH_NODE/AUTH_TAP
CONFIG_PUSH from SQLite runtime config
TapHub relay with MAC learning, flood limits, queue budget, and MAC freeze
session lifecycle persistence for node and TAP clients
nonblocking post-auth socket writer with select-based writable waits
signed HTTP API CRUD/get/grant/enable-disable/service endpoints
single-row API get endpoints
API timestamp skew and nonce replay checks
SOCKS5 username/password entrypoint with SQLite socks_users/socks_grants authorization
SOCKS stream OPEN/DATA/CLOSE relay to an online B node
SOCKS stream lifecycle persistence and in/out byte counters
SOCKS stream list/get API exposure for Web management
per-node max_socks_streams enforcement
node-level socks_idle_timeout_sec enforcement
node direct_port management and CONFIG_PUSH delivery
direct-token issue API for granted TAP users
```

Direct B-C data relay, SOCKS half-close hardening, Web management UI, and
OpenWrt packaging remain later-phase work.
