{
  description = "attested-tls-proxy with a reproducible attestation-provider-server OCI image";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      server = pkgs.rustPlatform.buildRustPackage {
        pname = "attestation-provider-server";
        version = "1.1.1";
        src = ./.;

        cargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            "attestation-0.0.1" = "sha256-1I9iQcFNt02fHs8Q18LK2+f8U0TzhfdFz7JvV0mKJUw=";
            "attested-tls-0.0.1" = "sha256-1I9iQcFNt02fHs8Q18LK2+f8U0TzhfdFz7JvV0mKJUw=";
            "cc-eventlog-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
            "cc-eventlog-0.5.8" = "sha256-KEauakj53LrhKTc0yYp5SM8ec0cFNm4YVuHCJYiPQjw=";
            "dcap-qvl-0.3.12" = "sha256-rLTp5wIhXRAcBtJb7lfd1TAg7yPRnwa0cBa1YT4LwKU=";
            "dstack-attest-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
            "dstack-types-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
            "nested-tls-0.0.1" = "sha256-1I9iQcFNt02fHs8Q18LK2+f8U0TzhfdFz7JvV0mKJUw=";
            "pccs-0.0.1" = "sha256-1I9iQcFNt02fHs8Q18LK2+f8U0TzhfdFz7JvV0mKJUw=";
            "ra-tls-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
            "size-parser-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
            "tdx-attest-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
            "tdx-attest-0.5.8" = "sha256-KEauakj53LrhKTc0yYp5SM8ec0cFNm4YVuHCJYiPQjw=";
          };
        };
        cargoBuildFlags = [ "-p" "attestation-provider-server" ];
        cargoHash = "sha256-rLTp5wIhXRAcBtJb7lfd1TAg7yPRnwa0cBa1YT4LwKU=";

        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.openssl pkgs.tpm2-tss ];

        doCheck = false;
      };

      imageRoot = pkgs.buildEnv {
        name = "attestation-provider-server-image-root";
        paths = [ server pkgs.cacert ];
        pathsToLink = [ "/bin" "/etc/ssl/certs" ];
      };
    in
    {
      packages.${system} = {
        attestation-provider-server = server;
        attestation-provider-server-image = pkgs.dockerTools.buildLayeredImage {
          name = "attestation-provider-server";
          tag = "latest";
          contents = [ imageRoot ];
          config = {
            Cmd = [
              "/bin/attestation-provider-server"
              "server"
              "--listen-transport"
              "vsock"
              "--vsock-port"
              "8000"
            ];
          };
        };
        default = self.packages.${system}.attestation-provider-server-image;
      };

      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [ pkg-config ];
        buildInputs = with pkgs; [ tpm2-tss openssl ];
      };
    };
}
