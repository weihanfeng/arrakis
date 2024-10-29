FROM ubuntu:20.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

ARG USERNAME=maverick
ARG PASSWORD=test0000
RUN useradd -m $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd && \
    adduser $USERNAME sudo

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
    python3-venv \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add any additional configurations or packages here
# TODO: Adding packages above rebuilds everything as its in one layer. Split them out and keep
# appending.
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
RUN . ~/.nvm/nvm.sh && nvm install 22

# Create a directory for your custom scripts
RUN mkdir -p /opt/custom_scripts

RUN chown root:root /usr/bin/sudo && chmod 4755 /usr/bin/sudo

# Helper scripts.
COPY out/chv-guestinit /opt/custom_scripts/guestinit
COPY out/chv-lambda-codeserver /opt/custom_scripts/chv-lambda-codeserver
COPY resources/scripts/rootfs/check-guest-networking.sh /opt/custom_scripts/.
COPY resources/scripts/rootfs/setup-guest-networking.sh /opt/custom_scripts/.
COPY resources/scripts/rootfs/init.sh /opt/custom_scripts/.
COPY resources/scripts/rootfs/vsock-test-server.py /opt/custom_scripts/.

# Custom Node and Python scripts can be put under "/opt/custom_scripts" and passed as "entry_point"
# in the client.
COPY resources/scripts/rootfs/server.js /opt/custom_scripts/.
COPY resources/scripts/rootfs/server.py /opt/custom_scripts/.

# Make sure the scripts are executable
RUN chmod +x /opt/custom_scripts/*
