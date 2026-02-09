{
  description = "apm2 development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.protobuf
            pkgs.git
            pkgs.rsync
            pkgs.ripgrep
            pkgs.gh
            pkgs.cargo-nextest
          ];

          env = {
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            RUST_BACKTRACE = "1";
            CARGO_TERM_COLOR = "always";
          };
        };
      }
    );
}
