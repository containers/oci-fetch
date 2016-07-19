# oci-fetch

Simple command line tool for fetching the [Open Container Initiative image format](https://github.com/opencontainers/image-spec) over various transports.

## Usage

```
$ go get github.com/containers/oci-fetch/oci-fetch
$ oci-fetch --help
oci-fetch will fetch an OCI image and store it on the local filesystem in a
.tar.gz file

Usage:
  oci-fetch docker://HOST/IMAGENAME[:TAG] FILEPATH [flags]

Examples:
oci-fetch docker://registry-1.docker.io/library/nginx:latest nginx.oci

Flags:
      --debug                            print out debugging information to stderr
  -h, --help                             help for oci-fetch
      --insecure-allow-http              don't enforce encryption when fetching images
      --insecure-skip-tls-verification   don't perform TLS certificate verification
```

## Current Status

oci-fetch can currently fetch OCI images from a [Docker v2 registry API](https://docs.docker.com/registry/spec/api/#pulling-an-image<Paste>).

## Future Roadmap

In the future we want to support additional transports such as:

- file transport based on the OCI Image Layout
- http transport based on the OCI Image Layout but for HTTP paths
- ftp transport based on the OCI Image Layout
- Bittorrent transport based on gzipped tarball of OCI Image Layout

## Contact

- Mailing list: [containers-dev](https://groups.google.com/forum/?hl=en#!forum/containers-dev)
- IRC: #[container-projects](irc://irc.freenode.org:6667/#container-projects) on freenode.org
