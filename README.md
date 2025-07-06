# I405 Tunnel: Constant-Traffic Padded IP Tunnel

I405 is the nuclear option for hiding network traffic: Send fixed-length encrypted UDP packets at
fixed, predetermined timestamps. Tunnelled traffic is transmitted by changing the encrypted content
of the packets. An attacker monitoring your network learns nothing about the tunneled traffic other than the maximum bandwidth.

![A bastardized version of the I405 interstate highway sign](i405-matrix.png)

The real power of I405 comes when you use I405 to establish an [Interstate
Circuit](./docs/interstate-circuits.md) to access the internet anonymously, kind of like Tor.
Interstate Circuits have very different privacy properties than Tor. For example, there's no P2P
network; you set up the whole circuit yourself! Interstate Circuits resist deanonymization by
"global passive adversaries", unlike Tor.

What's in the name? I405 tunnel implements "constant-traffic" padding. The I-405 freeway in LA
also has constant traffic!

## Documentation

+ [Interstate Circuits](./docs/interstate-circuits.md)
+ [Comparison of Interstate Circuits with Onion Routing (Tor, I2P) and Mixnets (Nym, Loopix, etc)](./docs/onion-mixnet-interstate-comparison.md)
+ [I405 Usage](./docs/usage.md)
+ [Real-time tuning](./docs/real-time-tuning.md)
+ [Contributing to I405](./CONTRIBUTING.md)

## Building and Testing

On most Linux distros, if you have the typical `build-essential` package or equivalent installed
(needed to compile our dependency `wolfssl-rs`), you can just run `cargo build` and other `cargo`
commands.

With Nix you can run `nix build` to compile using the included `flake.nix`. Similarly, you can use
`nix develop` to get a development environment.

Before a PR will be accepted, you must pass `cargo test -- --include-ignored` (slow tests are marked
with `#[ignore]`) and `sudo e2e_test.py`.
