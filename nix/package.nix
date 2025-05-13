{
  lib,

  automake,
  autoconf,
  libtool,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "i405-tunnel";
  version = "0.0.1";

  src = ./..;

  cargoLock.lockFile = ./../Cargo.lock;
  cargoLock.outputHashes."wolfssl-3.0.0" = "sha256-YbeAzZ4K245KtHkFQB04PMjDoO406eyIMnmC/c5SGco="; # interestingly, this doesn't seem to be verified during ~nix develop~!

  # All this to get wolfssl-rs to compile:
  nativeBuildInputs = [
    rustPlatform.bindgenHook
    automake
    autoconf
    libtool
  ];
}
