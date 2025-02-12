FROM ubuntu:22.04

# Avoid prompts from apt.
ENV DEBIAN_FRONTEND=noninteractive

ARG USERNAME=elara
ARG PASSWORD=elara0000
RUN useradd -m $USERNAME && \
    echo "$USERNAME:$PASSWORD" | chpasswd && \
    adduser $USERNAME sudo

# Needed to see journal logs.
RUN usermod -aG adm elara

# Set timezone.
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Update and install common utilities.
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
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
    xvfb \
    xfce4 \
    xfce4-goodies \
    zsh \
    tigervnc-standalone-server \
    socat \
    strace \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# To support sudo within the guest.
RUN chown root:root /usr/bin/sudo && chmod 4755 /usr/bin/sudo

# TODO: Tighten permissions on this directory after testing.
RUN mkdir -p /mnt/stateful && chmod 0777 /mnt/stateful

# Set up directory for the vsock server. This is required in case the overlayfs setup fails, we
# still need the vsockserver to be able to run.
RUN mkdir -p /tmp/vsockserver && chmod 0644 /tmp/vsockserver

# Add user binaries from the host into the guest rootfs in this section.
##############
RUN ln -s /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target

COPY out/chv-guestinit /usr/local/bin/chv-guestinit
RUN chmod +x /usr/local/bin/chv-guestinit
COPY resources/chv-guestinit.service /usr/lib/systemd/system/chv-guestinit.service
RUN ln -s /usr/lib/systemd/system/chv-guestinit.service /etc/systemd/system/multi-user.target.wants/chv-guestinit.service

COPY out/chv-cmdserver /usr/local/bin/chv-cmdserver
RUN chmod +x /usr/local/bin/chv-cmdserver
COPY resources/chv-cmdserver.service /usr/lib/systemd/system/chv-cmdserver.service
RUN ln -s /usr/lib/systemd/system/chv-cmdserver.service /etc/systemd/system/multi-user.target.wants/chv-cmdserver.service

COPY resources/chv-vncserver.service /usr/lib/systemd/system/chv-vncserver.service
RUN ln -s /usr/lib/systemd/system/chv-vncserver.service /etc/systemd/system/multi-user.target.wants/chv-vncserver.service

COPY out/chv-vsockserver /usr/local/bin/chv-vsockserver
RUN chmod +x /usr/local/bin/chv-vsockserver
COPY resources/chv-vsockserver.service /usr/lib/systemd/system/chv-vsockserver.service
RUN ln -s /usr/lib/systemd/system/chv-vsockserver.service /etc/systemd/system/multi-user.target.wants/chv-vsockserver.service

# Prevent the renaming service that will change "eth0" to "ens*". If not done our init service
# inside the guest has race conditions while configuring the network.
RUN ln -s /dev/null /etc/systemd/network/99-default.link
##############
