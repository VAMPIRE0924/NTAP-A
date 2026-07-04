# NTAP-A

NTAP-A is the public control and relay server for NTAP. It handles node registration, TAP user authentication, runtime configuration delivery, TAP frame relay, Direct strategy APIs, and the management API/Web entry point.

## Repository Set

NTAP is split into three clean source repositories. Deployable packages are published only through each repository's GitHub Releases.

- [NTAP-A](https://github.com/VAMPIRE0924/NTAP-A): public server, management API, SQLite state, node/TAP authentication, and TapHub relay.
- [NTAP-B](https://github.com/VAMPIRE0924/NTAP-B): node side, installed at the customer gateway or internal host, connects to A, and joins the local network.
- [NTAP-C](https://github.com/VAMPIRE0924/NTAP-C): client side, with a Windows GUI for customers and a Linux command-line entry point.

## Download And Deploy

Use the final packages from GitHub Releases. Do not deploy temporary files from a source checkout.

Latest release:

https://github.com/VAMPIRE0924/NTAP-A/releases/latest

Typical server package:

```text
NTAP-A-<version>-linux-x64.tar.gz
```

Basic deployment flow:

```sh
tar -xzf NTAP-A-<version>-linux-x64.tar.gz
cd NTAP-A-<version>-linux-x64
cp conf/ntap-a.conf.example conf/ntap-a.conf
```

Before the first run, edit the API key, listen addresses, SQLite path, and other deployment-specific settings.

Common commands from the release package:

```sh
bin/ntap-a -c conf/ntap-a.conf initdb
bin/ntap-a -c conf/ntap-a.conf serve
bin/ntap-a -c conf/ntap-a.conf api
```

The release package also includes service installation helpers for fixed-path deployment:

```sh
sudo sh install/install-linux-service.sh
sudo sh install/install-linux-service.sh --enable --start
```

## Source Scope

```text
src/a/       NTAP-A server source
src/common/  shared protocol and utility source
conf/        minimal example config
```

This repository keeps only source code, example config, README, and LICENSE. Final deployable packages live in GitHub Releases.

## Security Notes

- Change the default API key before exposing the API.
- Put SQLite data and logs under persistent directories.
- Split API/Web, TAP relay, and node connection listeners according to the deployment firewall plan.

## License

GPL-3.0-only. See `LICENSE`.
