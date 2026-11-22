# Northfire Services test image: Debian 12 (as on the network's services server)
# with the build tools and UnrealIRCd 6, for building and testing locally.
# Built by Kyle Bargman
FROM debian:bookworm
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config libargon2-dev libssl-dev ca-certificates curl perl \
      python3 libpcre2-dev libsodium-dev libc-ares-dev libcurl4-openssl-dev libjansson-dev zlib1g-dev openssl gettext \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m nfire
