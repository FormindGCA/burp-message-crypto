{
  description = "Development tools for the Burp message crypto extension";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/a7868a727837f3c09cee2ce0ca671c76b1589fed";
  outputs = { nixpkgs, ... }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    devShells.${system}.default = pkgs.mkShell {
      packages = [ pkgs.jdk21 pkgs.maven pkgs.python3 ];
      JAVA_HOME = "${pkgs.jdk21}";
    };
  };
}
