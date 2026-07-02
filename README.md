# NTAP-A

public control server, SQLite runtime config, AUTH_NODE/AUTH_TAP, TapHub relay, direct probe API, and CONFIG_PUSH direct strategy distribution.

This repository is exported from the NTAP integration workspace. Keep git
history source-only: do not commit build output, runtime databases, logs, or
generated release archives. Final release packages belong in GitHub Releases.

## Build

    make
    make config-test

## Layout

    src/common/  shared protocol and helpers
    src/a/  component source
    conf/        minimal example config

