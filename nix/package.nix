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

  meta = {
    description = "An encrypted constant-traffic padded network tunnel";
    homepage = "https://github.com/markasoftware/i405-tunnel";
    license = lib.licenses.mit;
    mainProgram = "i405-tunnel";
  };

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
  cargoLock.outputHashes."wolfssl-6.0.0" = "sha256-GQMuYuY99KKqflydzY9ly77JNx9tqM/l8pHnszQNuiY="; # interestingly, this doesn't seem to be verified during ~nix develop~!

  # All this to get wolfssl-rs to compile:
  nativeBuildInputs = [
    rustPlatform.bindgenHook
    automake
    autoconf
    libtool
  ];
}
