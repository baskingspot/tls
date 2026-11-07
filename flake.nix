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
      # Both toolchains are imported. The default shells build with the
      # current stable; `zig-old` is the previous one, for the compatibility
      # CI lane and local checks. The composition below names its version
      # once, so the compiler and the cache dirs commonHook sets agree.
      imports = with inputs.baskingspot.flakeModules; [
        base
        docs
        shell
        terraform
        zig."0.16"
        zig."0.17"
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
            zigTools
            openssl
            opensslBackend
            ;

          # Every tls shell carries the shared tool contract. Zig is a
          # parameter, not a copy: the same five definitions build the 0.17
          # set and the 0.16 one. `suffix` keeps the shell labels distinct.
          mkShells =
            {
              zig-shell,
              zig-tools,
              suffix,
            }:
            let
              tooling = [
                config.devShells.base
                config.devShells.shell
                config.devShells.terraform
                config.devShells.${zig-shell}
              ];
            in
            rec {
              # Lint against the oldest supported API surface from any shell,
              # so a 0.17-only deprecation does not fail a tree that must build
              # on 0.16.
              lint = [ config.packages."ziglint-0-16" ];

              # The repo's own toolset. The attr is `tls-base` because the
              # shared flake module owns `base`.
              tls-base = pkgs.mkShell {
                name = "tls-base${suffix}";
                inputsFrom = tooling;
                packages = commonPackages ++ lint;
                shellHook = commonHook zig-tools;
              };

              openssl = backendShell {
                name = "tls-openssl${suffix}";
                inputsFrom = tooling;
                inherit zig-tools;
                inherit (opensslBackend) pkgConfigPath;
                packages = lint ++ opensslBackend.packages;
              };

              aws-lc = backendShell {
                name = "tls-aws-lc${suffix}";
                inputsFrom = tooling;
                inherit zig-tools;
                pkgConfigPath = "${pkgs.aws-lc.dev}/lib/pkgconfig";
                packages = lint ++ [
                  pkgs.aws-lc.dev
                  pkgs.aws-lc
                ];
              };

              boringssl = backendShell {
                name = "tls-boringssl${suffix}";
                inputsFrom = tooling;
                inherit zig-tools;
                pkgConfigPath = "${boringsslPc}";
                packages = lint ++ [
                  pkgs.boringssl.dev
                  pkgs.boringssl
                ];
              };

              # The default shell plus the org's docs tooling: Zola, the
              # baskingspot theme, baskingspot-docs, and wrangler.
              default = pkgs.mkShell {
                name = "tls${suffix}";
                inputsFrom = [
                  openssl
                  config.devShells.docs
                ];
              };
            };

          current = mkShells {
            zig-shell = "zig-0-17";
            zig-tools = zigTools "0.17";
            suffix = "";
          };
          previous = mkShells {
            zig-shell = "zig-0-16";
            zig-tools = zigTools "0.16";
            suffix = "-old";
          };
        in
        {
          # Diagnostic provider for #121. Production keeps the optimized build.
          # GCC vector scans trigger Memcheck reports after valid NUL terminators.
          packages.openssl-memcheck = openssl.overrideAttrs (old: {
            configureFlags = old.configureFlags ++ [ "-fno-tree-vectorize" ];
          });

          devShells = {
            inherit (current) tls-base;
            inherit (current) openssl;
            inherit (current) aws-lc;
            inherit (current) boringssl;
            inherit (current) default;
            # The previous Zig. `just check` is the gate here; the full `ci`
            # runs on the default shell.
            zig-old = previous.default;
          };
        };
    };
}
