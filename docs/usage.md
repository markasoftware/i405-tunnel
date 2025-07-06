# I405 Usage
## Acquiring Binaries
   Download the latest Linux binaries from the releases section on Github.

   If the prebuilt binaries don't work for you, compile I405 as any Rust project -- install `cargo`
   and a typical C build toolchain (on Debian-like distros, `sudo apt install cargo
   build-essential`), then run `cargo build --release`. The binaries will be placed in the
   `target/release` folder.

   There's also a `flake.nix` file provided for Nix users, who can use this repository as a flake
   with `nix build` or `nix run` commands, eg `nix build github:markasoftware/i405-tunnel` will
   place binaries into the `result` folder.
## Important: Polling modes: Spinny vs Sleepy
   Feel free to play around with I405 first, but before using it for anything serious, I recommend
   at least skimming the [real-time tuning](./real-time-tuning.md) page to learn the difference
   between the "sleepy" and "spinny" poll modes, which affect how accurately I405 is able to send
   packest at the predetermined timestamps.
## CLI examples
   The canonical documentation for CLI options is in the help text, `i405-tunnel --help`. Here's a
   simple example of setting up a tunnel with 100 KiB/s upload and 1 MiB/s download. I take the
   server's public IP to be `1.2.3.4`; replace this with your server's real public IP. I use
   `10.140.5.1` as the server's IP in the tunnel and `10.140.5.2` as the client's IP in the tunnel;
   you can use these IPs exactly or change them to whatever you want. (In case you're unfamiliar
   with setting up layer-3 (IP) tunnels, you can set whatever IP you want inside the tunnel, which
   assigns to both client and server machines an additional IP address)

    On the server:

    ```
    i405-tunnel server --password passw0rd --tun-ipv4 10.140.5.1/24 # default: --listen-addr 0.0.0.0:1405
    ```

    On the client:

    ```
    i405-tunnel client --password passw0rd --tun-ipv4 10.140.5.2/24 --peer 1.2.3.4:1405 --up-speed 100k --down-speed 1m
    ```

    After this, run `ip link` on either machine and you should see the new `tun-i405` interfaces. Run `ip addr` and you should see the IP addresses assigned to each. Assuming your firewall is configured reasonably, you should also be able to ping across the tunnel at this point. Eg from the client: `ping 10.140.5.1`.

    To run an application on the server that's accessible over the tunnel, make sure it's listening either on `0.0.0.0` or specifically on `10.140.5.1`. If you do this for eg `sshd`, then you can now ssh to the server over the tunnel and nobody will be able to see when you're connected, or what you're doing over that ssh connection: `ssh 10.140.5.1`.
