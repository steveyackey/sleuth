{
  description = "sleuth: a fast, read-only disk-space detective for macOS and Linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # No x86_64-darwin: Nix and nixpkgs have dropped it. Intel Macs use cargo or the release binary.
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
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
