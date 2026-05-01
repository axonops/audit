# GoReleaser-driven Dockerfile for ghcr.io/axonops/audit-gen.
#
# GoReleaser builds the audit-gen binary on the host (per the
# `audit-gen` build entry in .goreleaser.yml) and copies it into
# this image as ./audit-gen. We do NOT compile inside the image —
# the binary is reproducibly built once per architecture and reused
# for both the GitHub release tarball and the OCI image. This keeps
# the image build hermetic and identical to the published binary.
#
# Base: gcr.io/distroless/static-debian12 — minimal, non-root,
# no shell, no package manager. Suitable for a self-contained Go
# binary that performs file I/O and stdout-only output.
FROM gcr.io/distroless/static-debian12:nonroot

# OCI labels (https://specs.opencontainers.org/image-spec/annotations/).
LABEL org.opencontainers.image.title="audit-gen"
LABEL org.opencontainers.image.description="Code generator for the github.com/axonops/audit library — produces typed Go event builders from a YAML taxonomy."
LABEL org.opencontainers.image.source="https://github.com/axonops/audit"
LABEL org.opencontainers.image.documentation="https://github.com/axonops/audit/blob/main/docs/code-generation.md"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="AxonOps Limited"

# GoReleaser drops the binary into the build context root.
COPY audit-gen /usr/local/bin/audit-gen

# Default working directory matches the documented usage:
#   docker run --rm -v $PWD:/src ghcr.io/axonops/audit-gen ...
WORKDIR /src

ENTRYPOINT ["/usr/local/bin/audit-gen"]
