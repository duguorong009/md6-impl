# MD6 Hash function

![Apache2/MIT licensed][license-image]


Pure Rust implementation of the [MD6] cryptographic hash algorithm.


## Examples

```rust
use md6::{Md6_256, Digest};
use hex_literal::hex;

let mut hasher = Md6_256::new();
hasher.update(b"md6");
let hash = hasher.finalize();

assert_eq!(hash, hex!("cbe8da56ff91be9bc299ed4c1da6159f9a41ab380f565db0a5ef08895aed4f7d"));
```

## Minimum Supported Rust Version

Rust **1.71** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg

[//]: # (general links)

[MD6]: https://en.wikipedia.org/wiki/MD6
