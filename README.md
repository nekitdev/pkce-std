# `pkce-std`

[![License][License Badge]][License]
[![Version][Version Badge]][Crate]
[![Downloads][Downloads Badge]][Crate]
[![Test][Test Badge]][Actions]

> *Handling Proof Key for Code Exchange.*

## Installation

### `cargo`

You can add `pkce-std` as a dependency with the following command:

```console
$ cargo add pkce-std
```

Or by directly specifying it in the configuration like so:

```toml
[dependencies]
pkce-std = "0.1.1"
```

Alternatively, you can add it directly from the source:

```toml
[dependencies.pkce-std]
git = "https://github.com/nekitdev/pkce-std.git"
```

## Example

```rust
use pkce_std::Code;

fn main() {
    let code = Code::generate_default();

    let (verifier, challenge) = code.into_pair();

    assert!(verifier.verify(&challenge));
}
```

## Documentation

You can find the documentation [here][Documentation].

## Support

If you need support with the library, you can send an [email][Email].

## Changelog

You can find the changelog [here][Changelog].

## Security Policy

You can find the Security Policy of `pkce-std` [here][Security].

## Contributing

If you are interested in contributing to `pkce-std`, make sure to take a look at the
[Contributing Guide][Contributing Guide], as well as the [Code of Conduct][Code of Conduct].

## License

`pkce-std` is licensed under the MIT License terms. See [License][License] for details.

[Email]: mailto:support@nekit.dev

[Discord]: https://nekit.dev/chat

[Actions]: https://github.com/nekitdev/pkce-std/actions

[Changelog]: https://github.com/nekitdev/pkce-std/blob/main/CHANGELOG.md
[Code of Conduct]: https://github.com/nekitdev/pkce-std/blob/main/CODE_OF_CONDUCT.md
[Contributing Guide]: https://github.com/nekitdev/pkce-std/blob/main/CONTRIBUTING.md
[Security]: https://github.com/nekitdev/pkce-std/blob/main/SECURITY.md

[License]: https://github.com/nekitdev/pkce-std/blob/main/LICENSE

[Crate]: https://crates.io/crates/pkce-std
[Documentation]: https://docs.rs/pkce-std

[License Badge]: https://img.shields.io/crates/l/pkce-std
[Version Badge]: https://img.shields.io/crates/v/pkce-std
[Downloads Badge]: https://img.shields.io/crates/dr/pkce-std
[Test Badge]: https://github.com/nekitdev/pkce-std/workflows/test/badge.svg
