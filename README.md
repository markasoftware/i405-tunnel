# I405 Tunnel: Constant-Traffic Padded Layer-3 Tunnel

I405 is the nuclear option for anonymizing network traffic. Tor and other tools have various schemes
of padding and delaying messages to make them hard to anonymize. (TODO: references to examples).
However, even the best padding schemes are vulnerable to statistical attacks. Machine learning (TODO
link) can deanonymize many fancy padding schemes. Even if you come up with a padding scheme that
resists current machine learning attacks, there are blunt ways to identify you: Eg, you usually only
turn on the software when you're using it, so attackers can correlate based on simply when there's
any network traffic over the anonymization protocol, padding or otherwise (TODO elaborate, also how
is I405 different than running eg a tor relay 24/7 in this respect?).

![A bastardized version of the I405 interstate highway sign](logo.svg)

## Using I405 as a Tor alternative: "Interstate Circuits"

I405 can be (carefully!) used to anonymously accessing clearnet websites.

TODO diagram

An Interstate Circuit consists of (at least) three network hops:
1. An I405 fully padded connection between your home internet and the "guard" server
2. A connection between the "guard" server and the "exit" server. You must have prior knowledge that
   this connection cannot be monitored by whoever you're hiding from. Eg, if you're trying to hide
   from Western governments, you might choose this hop to be between two servers in Russia;
   conversely, if you're trying to hide from the Russian government, you should make this hop
   between two servers in the Western world.
3. The final egress hop from your "exit" server to the ultimate clearnet site you're connecting to.

The attacker you're hiding from will be able to observe hops 1 and 3, but not 2. Because hops 1 and
3 do not involve the same servers, the attacker will not be able to simply use IP addresses to
correlate them. Furthermore, the observable network traffic on hop 1 is uniform and uncorrelated to
the actual data being tunnelled, so the attacker cannot determine that the traffic on hops 1 and 3
are correlated with any amount of statistical analysis.

For more details on how to securely set up an Interstate Circuit, see docs/interstate-circuits.md

## Building and Testing

On most Linux distros, if you have the typical `build-essential` package or equivalent installed
(needed to compile our dependency `wolfssl-rs`), you can just run `cargo build` and other `cargo`
commands.

With Nix you can run `nix build` to compile using the included `flake.nix`. Similarly, you can use
`nix develop` to get a development environment.

Before a PR will be accepted, you must pass `cargo test -- --include-ignored` (slow tests are marked
with `#[ignore]`) and `sudo end-to-end-tests/e2e_test.py`.
