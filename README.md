# oci-fetch

This project implements fetching the [Open Container Initiative image format](https://github.com/opencontainers/image-spec) over the Docker registry API.

## Usage

```
$ go get github.com/containers/oci-fetch
$ oci-fetch --help
Usage:
  oci-fetch HOST/IMAGENAME[:TAG] FILEPATH [flags]

Examples:
oci-fetch registry-1.docker.io/library/nginx:latest nginx.oci

Flags:
      --debug                            print out debugging information to stderr
  -h, --help                             help for oci-fetch
      --insecure-allow-http              don't enforce encryption when fetching images
      --insecure-skip-tls-verification   don't perform TLS certificate verification
```

## Future Roadmap

In the future we want to support additional transports such as:

- file transport based on the OCI Image Layout
- http transport based on the OCI Image Layout but for HTTP paths
- ftp transport based on the OCI Image Layout
- Bittorrent transport based on gzipped tarball of OCI Image Layout
