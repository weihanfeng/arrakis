FROM ubuntu:20.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

ARG USERNAME=elara
ARG PASSWORD=elara0000
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

# To support sudo within the guest.
RUN chown root:root /usr/bin/sudo && chmod 4755 /usr/bin/sudo

# Add custom binaries from the host into the guest rootfs in this section.
##############
COPY out/chv-guestinit /opt/custom_scripts/guestinit
COPY out/chv-lambda-codeserver /opt/custom_scripts/chv-lambda-codeserver
COPY out/chv-lambda-cmdserver /opt/custom_scripts/chv-lambda-cmdserver
##############

# Make sure the scripts are executable
RUN chmod +x /opt/custom_scripts/*

# Install the server that will execute react code.
ENV PATH=$PATH:/usr/bin/versions/node/v22.11.0/bin
# TODO: Giving absolute paths to `npm create` isn't respected, hence we use WORKDIR.
WORKDIR /opt/custom_scripts/node_code_server
RUN npm create vite@latest . -- --template react-ts 2>&1
RUN npm install 2>&1
