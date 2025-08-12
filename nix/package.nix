{
  lib,

  automake,
  autoconf,
  libtool,
  rustPlatform,
}:

let fs = lib.fileset;
in

rustPlatform.buildRustPackage {
  pname = "i405-tunnel";
  version = "0.1.1";

  src = fs.toSource {
    root = ./..;
    fileset = fs.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
      ../tests
    ];
  };

  cargoLock.lockFile = ./../Cargo.lock;
  cargoLock.outputHashes."wolfssl-3.0.0" = "sha256-TqIk+A52jrWUMApFSWNqwJ5LJPZJGwO00Gxj3KWYDaU="; # interestingly, this doesn't seem to be verified during ~nix develop~!

  # All this to get wolfssl-rs to compile:
  nativeBuildInputs = [
    rustPlatform.bindgenHook
    automake
    autoconf
    libtool
  ];
}
