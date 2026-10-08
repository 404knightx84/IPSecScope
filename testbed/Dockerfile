FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan-charon strongswan-swanctl \
    libstrongswan-standard-plugins libstrongswan-extra-plugins \
    libcharon-extra-plugins \
    iproute2 iputils-ping tcpdump ethtool iptables curl net-tools python3 ffmpeg \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
