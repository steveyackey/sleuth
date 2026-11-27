{
  description = "sleuth: a fast, read-only disk-space detective for macOS and Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # nixpkgs dropped x86_64-darwin after 26.05; Intel Macs build from the last branch that has it.
    nixpkgs-intel-darwin.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  };

  outputs = { self, nixpkgs, nixpkgs-intel-darwin }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      pkgsFor = system: (if system == "x86_64-darwin" then nixpkgs-intel-darwin else nixpkgs).legacyPackages.${system};
      forAll = f: nixpkgs.lib.genAttrs systems (system: f (pkgsFor system));
      manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
    in
    {
      packages = forAll (pkgs: rec {
        sleuth = pkgs.rustPlatform.buildRustPackage {
          pname = "sleuth";
          inherit (manifest.package) version;
          src = pkgs.lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          meta = {
            description = manifest.package.description;
            mainProgram = "sleuth";
            platforms = systems;
          };
        };
        default = sleuth;
      });

      apps = forAll (pkgs: rec {
        sleuth = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.sleuth}/bin/sleuth";
          meta.description = "Find what's eating your disk (read-only)";
        };
        default = sleuth;
      });

      overlays.default = final: _prev: { sleuth = self.packages.${final.stdenv.hostPlatform.system}.sleuth; };

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer ];
          # Conventional Commits check on every commit (see commitlint.config.mjs).
          shellHook = ''
            git config core.hooksPath .githooks 2>/dev/null || true
          '';
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt);
    };
}
