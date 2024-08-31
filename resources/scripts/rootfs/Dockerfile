FROM ubuntu:20.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Set timezone
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Update and install common utilities
RUN apt-get update && apt-get install -y \
    init \
    systemd \
    ncat \
    bash \
    curl \
    wget \
    vim \
    nano \
    git \
    htop \
    net-tools \
    iputils-ping \
    iproute2 \
    traceroute \
    dnsutils \
    tcpdump \
    netcat \
    ssh \
    sudo \
    man-db \
    less \
    procps \
    psmisc \
    lsof \
    rsync \
    tar \
    gzip \
    zip \
    unzip \
    ca-certificates \
    tzdata \
    tini \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add any additional configurations or packages here

# Create a directory for your custom scripts
RUN mkdir -p /opt/custom_scripts

# Copy your custom scripts into the image
COPY check-guest-networking.sh /opt/custom_scripts/.
COPY setup-guest-networking.sh /opt/custom_scripts/.
COPY init.sh /opt/custom_scripts/.
COPY vsock-test-server.py /opt/custom_scripts/.

# Make sure the scripts are executable
RUN chmod +x /opt/custom_scripts/*.sh
