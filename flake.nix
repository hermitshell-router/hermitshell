{
  description = "HermitShell — open-source router platform";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, rust-overlay, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            targets = [ "${system}-unknown-linux-musl" ];
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          src = craneLib.cleanCargoSource ./.;

          commonArgs = {
            inherit src;
            strictDeps = true;
            CARGO_BUILD_TARGET = "${system}-unknown-linux-musl";
            LEPTOS_OUTPUT_NAME = "hermitshell";
            nativeBuildInputs = with pkgs; [
              pkg-config
              perl       # for vendored OpenSSL build
              cmake      # for aws-lc-sys
            ];
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        in
        {
          default = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            cargoExtraArgs = "-p hermitshell-agent -p hermitshell-dhcp -p hermitshell";

            installPhaseCommand = ''
              mkdir -p $out/bin
              target_dir="target/${system}-unknown-linux-musl/release"
              cp "$target_dir/hermitshell-agent" $out/bin/
              cp "$target_dir/hermitshell-dhcp" $out/bin/
              cp "$target_dir/hermitshell" $out/bin/hermitshell-ui
            '';
          });
        }
      );

      nixosModules.default = import ./nix/module.nix self;

      checks = forAllSystems (system: {
        package = self.packages.${system}.default;
      });
    };
}
