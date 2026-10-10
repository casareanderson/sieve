# sieve in a container. Host scans read the host's filesystem mounted read-only:
#   docker run --rm -v /:/host:ro ghcr.io/casareanderson/sieve host --root /host
# Container scans need the docker CLI and root on the Docker host, so run the collector there and pipe it in:
#   docker run --rm ghcr.io/casareanderson/sieve collector | sudo python3 - \
#     | docker run --rm -i ghcr.io/casareanderson/sieve containers --from-tar -
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/casareanderson/sieve" \
      org.opencontainers.image.description="Find the CVEs that matter on a Linux box and its running containers" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

COPY . /src
RUN pip install --no-cache-dir --disable-pip-version-check /src && rm -rf /src \
 && useradd --create-home --uid 10001 sieve \
 && mkdir -p /home/sieve/.cache/sieve && chown -R sieve:sieve /home/sieve/.cache

# Package databases and dist-info metadata are world-readable, so host scans don't need root.
USER sieve
ENTRYPOINT ["sieve"]
CMD ["--help"]
