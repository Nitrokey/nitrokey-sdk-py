# Nitrokey Python SDK

The Nitrokey Python SDK can be used to use and configure Nitrokey devices.

## Installation

The Nitrokey Python SDK has not been released yet.
You can install the current version from GitHub using the following command:

```
$ pip install "nitrokey @ git+https://github.com/Nitrokey/nitrokey-sdk-py.git"
```

## Compatibility

The Nitrokey Python SDK currently requires Python 3.9 or later.
Support for old Python versions may be dropped in minor releases.

## Related Projects

- [pynitrokey](https://github.com/Nitrokey/pynitrokey):
  A command line interface for the Nitrokey FIDO2, Nitrokey Start, Nitrokey 3 and NetHSM
- [nitrokey-app2](https://github.com/nitrokey/nitrokey-app2):
  A graphical application to manage and use Nitrokey 3 devices
- [nethsm-sdk-py](https://github.com/Nitrokey/nethsm-sdk-py):
  A client-side Python SDK for NetHSM

## Development

The following software is required for the development of the SDK:

- Python 3.9 or newer
- [poetry](https://python-poetry.org/)
- GNU Make
- git

After checking out the source code from GitHub, you can install the SDK and its dev dependencies into a new virtual environment managed by poetry using `make install`:

```
$ git clone https://github.com/Nitrokey/nitrokey-sdk-py.git
$ cd nitrokey-sdk-py
$ make install
```

We use multiple checks and linters for this project.
Use `make check` to run all required checks.
Some problems can automatically be fixed by running `make fix`.

The SDK also includes minimal tests to ensure that it is installed and loaded correctly.
Use `make test` to run these tests.

### Dependency Management

We use [poetry](https://python-poetry.org) for dependency management.
poetry maintains a lockfile with pinned dependency versions that is used for development environments and in CI.
This lockfile includes the hash of the `pyproject.toml` file, so it needs to be updated if `pyproject.toml` is changed.
These make targets can be used to invoke poetry for the most common tasks:

- `make install` installs the SDK and its dependencies as specified in the lockfile (must be up-to-date)
- `make lock` updates the lockfile without changing pinned dependency versions
- `make update` bumps all dependencies, installs them and updates the lockfile

For more information, see poetry’s documentation on [Managing depencies](https://python-poetry.org/docs/managing-dependencies/) and [Commands](https://python-poetry.org/docs/cli/).

## License

This software is fully open source.

All software, unless otherwise noted, is dual licensed under [Apache 2.0](./LICENSES/Apache-2.0.txt) and [MIT](./LICENSES/MIT.txt).
You may use the software under the terms of either the Apache 2.0 license or MIT license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.