{
  description = "apm2 — Holonic AI Process Manager: devShell, packages, and apps";

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

        # Native build inputs required by workspace crates:
        #   - protobuf:  prost-build compiles .proto files (apm2-core, apm2-daemon)
        #   - pkg-config: locates system libraries for C dependencies
        nativeBuildDeps = [
          pkgs.protobuf
          pkgs.pkg-config
        ];

        # Runtime/link-time dependencies:
        #   - openssl: TLS for HTTP client (hyper-rustls ring backend needs libring build)
        #   - dbus:    zbus D-Bus IPC (apm2-daemon)
        buildDeps = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
          pkgs.dbus
        ];

        # Common environment variables for builds
        buildEnv = {
          PROTOC = "${pkgs.protobuf}/bin/protoc";
        };

        # ---------------------------------------------------------------
        # Optional Nix packages for reproducible deployment.
        #
        # These use rustPlatform.buildRustPackage with the same toolchain
        # pinned in rust-toolchain.toml via rust-overlay.
        # ---------------------------------------------------------------
        commonRustPkgArgs = {
          pname = "apm2";
          version =
            let
              cargo = builtins.fromTOML (builtins.readFile ./Cargo.toml);
            in
            cargo.workspace.package.version;

          src = pkgs.lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = nativeBuildDeps;
          buildInputs = buildDeps;

          env = buildEnv;

          doCheck = false; # Tests run in CI; skip in Nix build for speed
        };

        apm2-cli = pkgs.rustPlatform.buildRustPackage (commonRustPkgArgs // {
          pname = "apm2-cli";
          cargoBuildFlags = [ "--package" "apm2-cli" ];

          meta = {
            description = "CLI client for apm2 — AI process manager";
            homepage = "https://github.com/guardian-intelligence/apm2";
            license = with pkgs.lib.licenses; [ mit asl20 ];
            mainProgram = "apm2";
          };
        });

        apm2-daemon = pkgs.rustPlatform.buildRustPackage (commonRustPkgArgs // {
          pname = "apm2-daemon";
          cargoBuildFlags = [ "--package" "apm2-daemon" ];

          meta = {
            description = "Daemon binary for apm2 — AI process manager";
            homepage = "https://github.com/guardian-intelligence/apm2";
            license = with pkgs.lib.licenses; [ mit asl20 ];
            mainProgram = "apm2-daemon";
          };
        });
      in
      {
        # ----- Dev shell (primary deliverable of this ticket) -----
        devShells.default = pkgs.mkShell {
          packages =
            [
              rustToolchain

              # Build tools
              pkgs.cargo-nextest

              # VCS + CI tools
              pkgs.git
              pkgs.gh

              # Utilities used by FAC scripts and agent workflows
              pkgs.rsync
              pkgs.ripgrep
              pkgs.jq
            ]
            ++ nativeBuildDeps
            ++ buildDeps;

          env = buildEnv // {
            RUST_BACKTRACE = "1";
            CARGO_TERM_COLOR = "always";
          };

          shellHook = ''
            echo "apm2 dev shell ready  ($(rustc --version))"
            echo "  cargo nextest:  $(cargo nextest --version 2>/dev/null || echo 'not found')"
            echo "  protoc:         $(protoc --version 2>/dev/null || echo 'not found')"
            echo ""
            echo "Quick start:"
            echo "  cargo build --workspace          # build all crates"
            echo "  cargo nextest run --workspace     # run tests with nextest"
            echo "  cargo clippy --workspace --all-targets --all-features -- -D warnings"
            echo ""
          '';
        };

        # ----- Optional packages -----
        packages = {
          inherit apm2-cli apm2-daemon;
          default = apm2-cli;
        };

        # ----- Apps (nix run) -----
        apps = {
          apm2 = flake-utils.lib.mkApp { drv = apm2-cli; };
          apm2-daemon = flake-utils.lib.mkApp {
            drv = apm2-daemon;
            name = "apm2-daemon";
          };
          default = flake-utils.lib.mkApp { drv = apm2-cli; };
        };
      }
    );
}
