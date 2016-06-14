# oci-fetch-docker

The Open Container Initiative contains a specification for an image format.

This project implements fetching this image format over the Docker registry API.

## Future Roadmap

In the future we might support additional transports such as:

- file transport based on the OCI Image Layout
- http transport based on the OCI Image Layout but for HTTP paths
- ftp transport based on the OCI Image Layout
- Bittorrent transport based on gzipped tarball of OCI Image Layout
