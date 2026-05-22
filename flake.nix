{
  description = "attested-tls-proxy with a reproducible attestation-provider-server OCI image";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      # Both workspace members share a single Cargo.lock, so their dependency
      # hashes are identical.  Keeping this in one place means a lockfile bump
      # only requires updating hashes here.
      #
      # Note: mock-tdx-0.0.1 appears twice in the lockfile (peg/nitro transitive
      # dep and main-branch dev-dep).  The peg/nitro rev is shared with
      # attestation-0.0.1 (same SHA → same hash).  The main-branch entry is
      # stripped by cleanedLockFile below, so no hash entry is needed for it.
      sharedOutputHashes = {
        "attestation-0.0.1" = "sha256-4wa8gP9xQCZZL4JUnb1fNfpwxcahec5SgYZamdqX2h8=";
        "attested-tls-0.0.1" = "sha256-4wa8gP9xQCZZL4JUnb1fNfpwxcahec5SgYZamdqX2h8=";
        "cc-eventlog-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
        "cc-eventlog-0.5.8" = "sha256-KEauakj53LrhKTc0yYp5SM8ec0cFNm4YVuHCJYiPQjw=";
        "dcap-qvl-0.3.12" = "sha256-rLTp5wIhXRAcBtJb7lfd1TAg7yPRnwa0cBa1YT4LwKU=";
        "dstack-attest-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
        "dstack-types-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
        "nested-tls-0.0.1" = "sha256-4wa8gP9xQCZZL4JUnb1fNfpwxcahec5SgYZamdqX2h8=";
        "pccs-0.0.1" = "sha256-4wa8gP9xQCZZL4JUnb1fNfpwxcahec5SgYZamdqX2h8=";
        "ra-tls-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
        "size-parser-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
        "tdx-attest-0.5.11" = "sha256-q6Vrlx4N7Ce2EQTQH+0HCSEzFZmY8PzDHxrO8L3kMsQ=";
        "tdx-attest-0.5.8" = "sha256-KEauakj53LrhKTc0yYp5SM8ec0cFNm4YVuHCJYiPQjw=";
      };

      # nixpkgs importCargoLock creates one symlink per package keyed by
      # "<name>-<version>".  When two git crates share the same name+version
      # (here: mock-tdx-0.0.1 from peg/nitro and from main), the second ln
      # follows the first symlink into a read-only store path and fails.
      #
      # The main-branch entry is a dev-dep of attested-tls-proxy only; since
      # doCheck = false it is never compiled.  Strip it from the lockfile at
      # evaluation time so importCargoLock only ever sees the peg/nitro
      # transitive dep (already covered by the attestation-0.0.1 hash above).
      cleanedLockFile = builtins.toFile "Cargo.lock" (
        builtins.replaceStrings
          [
            # [[package]] block for mock-tdx (main branch).
            # The leading \n eats the blank separator line before the block;
            # the trailing blank line before peg/nitro mock-tdx is preserved.
            "\n[[package]]\nname = \"mock-tdx\"\nversion = \"0.0.1\"\nsource = \"git+https://github.com/flashbots/attested-tls?branch=main#eaa10f0528c8c561273717913596de65cff807b3\"\ndependencies = [\n \"axum\",\n \"dcap-qvl\",\n \"hex\",\n \"p256\",\n \"parity-scale-codec\",\n \"rcgen 0.14.7\",\n \"serde\",\n \"serde-saphyr\",\n \"serde_bytes\",\n \"serde_json\",\n \"sha2\",\n \"time\",\n \"tokio\",\n \"urlencoding\",\n \"x509-parser 0.18.1\",\n \"yasna 0.5.2\",\n]\n"
            # Dep reference in the attested-tls-proxy package entry
            # (Cargo.lock dep references omit the #rev suffix)
            " \"mock-tdx 0.0.1 (git+https://github.com/flashbots/attested-tls?branch=main)\",\n"
          ]
          [ "" "" ]
          (builtins.readFile ./Cargo.lock)
      );

      # Vendor directory built from the cleaned lockfile (no mock-tdx main branch).
      sharedCargoDeps = pkgs.rustPlatform.importCargoLock {
        lockFile = cleanedLockFile;
        outputHashes = sharedOutputHashes;
      };

      # Patch the unpacked source to match the vendor dir:
      # cargo reads the source's Cargo.lock at build time and requires it to
      # be consistent with what is vendored.
      sharedPostUnpack = ''
        cp ${cleanedLockFile} "$sourceRoot/Cargo.lock"
        chmod u+w "$sourceRoot/Cargo.lock"
        sed -i '/^mock-tdx/d' "$sourceRoot/Cargo.toml"
      '';

      sharedBuildInputs = [ pkgs.openssl pkgs.tpm2-tss ];
      sharedNativeBuildInputs = [ pkgs.pkg-config ];

      server = pkgs.rustPlatform.buildRustPackage {
        pname = "attestation-provider-server";
        version = "1.1.1";
        src = ./.;

        cargoDeps = sharedCargoDeps;
        postUnpack = sharedPostUnpack;
        cargoBuildFlags = [ "-p" "attestation-provider-server" ];

        nativeBuildInputs = sharedNativeBuildInputs;
        buildInputs = sharedBuildInputs;

        doCheck = false;
      };

      proxy = pkgs.rustPlatform.buildRustPackage {
        pname = "attested-tls-proxy";
        version = "1.1.1";
        src = ./.;

        cargoDeps = sharedCargoDeps;
        postUnpack = sharedPostUnpack;
        cargoBuildFlags = [ "-p" "attested-tls-proxy" ];

        nativeBuildInputs = sharedNativeBuildInputs;
        buildInputs = sharedBuildInputs;

        doCheck = false;
      };

      serverImageRoot = pkgs.buildEnv {
        name = "attestation-provider-server-image-root";
        paths = [ server pkgs.cacert ];
        pathsToLink = [ "/bin" "/etc/ssl/certs" ];
      };

      proxyImageRoot = pkgs.buildEnv {
        name = "attested-tls-proxy-image-root";
        paths = [ proxy pkgs.cacert ];
        pathsToLink = [ "/bin" "/etc/ssl/certs" ];
      };

      # A single text file at /srv/hello.txt for testing the file server image.
      # writeTextDir "srv/hello.txt" produces $out/srv/hello.txt, which buildEnv
      # links into /srv/hello.txt inside the image.
      testContent = pkgs.writeTextDir "srv/hello.txt"
        "Hello from attested-file-server!\n";

      # Nitro enclaves don't bring up the loopback interface by default.
      # The file server binds axum on 127.0.0.1 and the proxy connects back to
      # it over loopback, so lo must be up before the binary starts.
      fileServerEntrypoint = pkgs.writeShellScriptBin "attested-file-server-start" ''
        ${pkgs.iproute2}/bin/ip link set lo up
        exec ${proxy}/bin/attested-tls-proxy "$@"
      '';

      fileServerImageRoot = pkgs.buildEnv {
        name = "attested-file-server-image-root";
        paths = [ fileServerEntrypoint pkgs.cacert testContent ];
        pathsToLink = [ "/bin" "/etc/ssl/certs" "/srv" ];
      };
    in
    {
      packages.${system} = {
        attestation-provider-server = server;
        attestation-provider-server-image = pkgs.dockerTools.buildLayeredImage {
          name = "attestation-provider-server";
          tag = "latest";
          contents = [ serverImageRoot ];
          config = {
            Cmd = [
              "/bin/attestation-provider-server"
              "server"
              "--listen-transport"
              "vsock"
              "--vsock-port"
              "8000"
              "--server-attestation-type"
              "aws-nitro"
            ];
          };
        };

        attested-tls-proxy = proxy;
        attested-tls-proxy-server-image = pkgs.dockerTools.buildLayeredImage {
          name = "attested-tls-proxy-server";
          tag = "latest";
          contents = [ proxyImageRoot ];
          config = {
            # Global flags must precede the subcommand.
            # --allowed-remote-attestation-type satisfies the mandatory CLI
            # requirement; it only takes effect when --client-auth is passed.
            # target_addr is a required positional arg supplied via Cmd so it
            # can be overridden at runtime:
            #   docker run attested-tls-proxy-server 127.0.0.1:8080
            Entrypoint = [
              "/bin/attested-tls-proxy"
              "--allowed-remote-attestation-type"
              "aws-nitro"
              "server"
              "--server-attestation-type"
              "aws-nitro"
              "--inner-vsock-port"
              "8001"
            ];
            Cmd = [ "127.0.0.1:3000" ];
          };
        };

        attested-file-server-image = pkgs.dockerTools.buildLayeredImage {
          name = "attested-file-server";
          tag = "latest";
          contents = [ fileServerImageRoot ];
          config = {
            # attested-file-server starts an internal HTTP server on a random
            # loopback port, then wraps it with an attested TLS listener.
            # path_to_serve (/srv) is the positional arg after the subcommand.
            # --inner-listen-addr is TCP-only (no vsock on this subcommand).
            # Retrieve the test file with:
            #   attested-tls-proxy ... attested-get <host>:8002 --url-path /hello.txt
            Entrypoint = [
              "/bin/attested-file-server-start"
              "--allowed-remote-attestation-type"
              "aws-nitro"
              "attested-file-server"
              "/srv"
              "--server-attestation-type"
              "aws-nitro"
              "--inner-vsock-port"
              "8002"
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
