{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.follows = "baskingspot/flake-parts";
    baskingspot = {
      url = "github:baskingspot/nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mattware = {
      url = "github:mattrobenolt/nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      flake-parts,
      nixpkgs,
      mattware,
      rust-overlay,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # imports and inputsFrom below mirror each other, except the toolchain
      # version: pick that once, in the import.
      imports = with inputs.baskingspot.flakeModules; [
        base
        docs
        shell
        terraform
        zig."0.16"
      ];

      perSystem =
        {
          system,
          lib,
          config,
          ...
        }:
        let
          # The mattware overlay carries the openssl 3.6 line and the rust
          # toolchain the benchmark harness pins. The shared modules keep the
          # default package set; they only supply tools to the shells below.
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              mattware.overlays.default
              rust-overlay.overlays.default
            ];
          };
          shared = import ./nix/shared.nix { inherit pkgs lib; };
          inherit (shared)
            commonPackages
            commonHook
            boringsslPc
            backendShell
            zig
            openssl
            opensslBackend
            ;
          # Every tls shell carries the shared tool contract. Qualify each
          # name: `zig` in this scope is the toolchain helper below.
          tooling = [
            config.devShells.base
            config.devShells.shell
            config.devShells.terraform
            config.devShells.zig
          ];
        in
        {
          # Diagnostic provider for #121. Production keeps the optimized build.
          # GCC vector scans trigger Memcheck reports after valid NUL terminators.
          packages.openssl-memcheck = openssl.overrideAttrs (old: {
            configureFlags = old.configureFlags ++ [ "-fno-tree-vectorize" ];
          });

          devShells = rec {
            # The repo's own toolset. The attr is `tls-base` because the
            # shared flake module owns `base`.
            tls-base = pkgs.mkShell {
              name = "tls-base";
              inputsFrom = tooling;
              packages = commonPackages;
              shellHook = commonHook zig;
            };

            openssl = backendShell {
              name = "tls-openssl";
              inputsFrom = tooling;
              inherit (opensslBackend) pkgConfigPath packages;
            };

            aws-lc = backendShell {
              name = "tls-aws-lc";
              inputsFrom = tooling;
              pkgConfigPath = "${pkgs.aws-lc.dev}/lib/pkgconfig";
              packages = [
                pkgs.aws-lc.dev
                pkgs.aws-lc
              ];
            };

            boringssl = backendShell {
              name = "tls-boringssl";
              inputsFrom = tooling;
              pkgConfigPath = "${boringsslPc}";
              packages = [
                pkgs.boringssl.dev
                pkgs.boringssl
              ];
            };

            # The default shell plus the org's docs tooling: Zola, the
            # baskingspot theme, baskingspot-docs, and wrangler.
            default = pkgs.mkShell {
              name = "tls";
              inputsFrom = [
                openssl
                config.devShells.docs
              ];
            };
          };
        };
    };
}
