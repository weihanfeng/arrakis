FROM ubuntu:20.04

# Avoid prompts from apt.
ENV DEBIAN_FRONTEND=noninteractive

ARG USERNAME=elara
ARG PASSWORD=elara0000
RUN useradd -m $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd && \
    adduser $USERNAME sudo

# Set timezone.
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Update and install common utilities.
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

# Dependencies for executing TS and React code.
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
RUN . ~/.nvm/nvm.sh && nvm install 22
ENV PATH=$PATH:/usr/bin/versions/node/v22.11.0/bin

# Create a directory for your custom scripts
RUN mkdir -p /opt/custom_scripts

# To support sudo within the guest.
RUN chown root:root /usr/bin/sudo && chmod 4755 /usr/bin/sudo

# Add user binaries from the host into the guest rootfs in this section.
##############
COPY out/chv-guestinit /opt/custom_scripts/guestinit

# Optional binary that helps execute code.
#COPY out/chv-codeserver /opt/custom_scripts/chv-lambda-codeserver

# Optional binary that helps execute shell commands.
#COPY out/chv-cmdserver /opt/custom_scripts/chv-lambda-cmdserver
##############

# Make sure the user binaries are executable.
RUN chmod +x /opt/custom_scripts/*
