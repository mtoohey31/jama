{
  description = "jama";

  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }: utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };
      inherit (pkgs) go gopls man-pages man-pages-posix mkShell;
    in
    {
      devShells.default = mkShell {
        packages = [ go gopls man-pages man-pages-posix ];
      };
    });
}
