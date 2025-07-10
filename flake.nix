{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
        eachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f system nixpkgs.legacyPackages.${system});
        package-nix = import ./nix/package.nix;
    in {
      packages = eachSupportedSystem (system: pkgs: {
        default = pkgs.callPackage package-nix {};
      });

      devShells = eachSupportedSystem (system: pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.rust-analyzer pkgs.clippy pkgs.iperf3 pkgs.tcpdump ];
          inputsFrom = [ self.packages.${system}.default ];
        };
      });
    };
}
