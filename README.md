# I405 Tunnel: Constant-Traffic padded and encrypted tunnel

If you *really* want to make sure people can't inspect your network traffic, this tunnel is for you.
It completely hides network traffic metadata by sending packets whose sizes and timings are chosen
without knowledge of the data being sent. When data needs to be sent through the tunnel, each packet
is padded to the predetermined size and encrypted with DTLS.

## Building

On most Linux distros, if you have the typical `build-essential` package or equivalent installed
(needed to compile our dependency `wolfssl-rs`), you can just run `cargo build` and other `cargo`
commands.

With Nix you can run `nix build` to compile using the included `flake.nix`. Similarly, you can use
`nix develop` to get a development environment.
