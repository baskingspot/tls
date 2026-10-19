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
          # Every ztls shell carries the shared tool contract. Qualify each
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
            # The repo's own toolset. The attr is `ztls-base` because the
            # shared flake module owns `base`.
            ztls-base = pkgs.mkShell {
              name = "ztls-base";
              inputsFrom = tooling;
              packages = commonPackages;
              shellHook = commonHook zig;
            };

            openssl = backendShell {
              name = "ztls-openssl";
              inputsFrom = tooling;
              inherit (opensslBackend) pkgConfigPath packages;
            };

            aws-lc = backendShell {
              name = "ztls-aws-lc";
              inputsFrom = tooling;
              pkgConfigPath = "${pkgs.aws-lc.dev}/lib/pkgconfig";
              packages = [
                pkgs.aws-lc.dev
                pkgs.aws-lc
              ];
            };

            boringssl = backendShell {
              name = "ztls-boringssl";
              inputsFrom = tooling;
              pkgConfigPath = "${boringsslPc}";
              packages = [
                pkgs.boringssl.dev
                pkgs.boringssl
              ];
            };

            # Docs site tooling: Zig autodoc build plus mdBook and wrangler
            # for building and publishing the Cloudflare site. Built on the
            # OpenSSL backend shell. The org's `docs` module is Zola, so this
            # stays repo-local until the site moves in a later phase.
            docs = backendShell {
              name = "ztls-docs";
              inputsFrom = tooling;
              inherit (opensslBackend) pkgConfigPath;
              packages = opensslBackend.packages ++ [
                pkgs.mdbook
                pkgs.nodejs
                shared.wrangler
              ];
            };

            # Brand asset tooling (wordmark/logo generation). Kept out of the
            # common dev shell so ztls devs don't carry font/Python deps.
            brand = pkgs.mkShell {
              name = "ztls-brand";
              inputsFrom = [ config.devShells.base ];
              packages = [
                (pkgs.python3.withPackages (ps: [ ps.fonttools ]))
                pkgs.jetbrains-mono
              ];
              shellHook = ''
                export ZTLS_BRAND_FONT_DIR=${pkgs.jetbrains-mono}/share/fonts
              '';
            };

            default = openssl;
          };
        };
    };
}
