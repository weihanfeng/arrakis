# chv-starter-pack

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

- MicroVMs are lightweight Virtual Machines (compared to traditional VMs) powered by Rust based Virtual Machine Managers such as [firecracker](https://github.com/firecracker-microvm/firecracker) and [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor).

- **chv-starter-pack** provides everything required to get started with creating, managing and configuring [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) based MicroVMs locally on Linux based machines.

---

## Features

`chv-starter-pack` includes the following services and features -

- **chv-restserver**
  - A daemon that exposes a REST API to *start*, *stop*, *destroy*, *list-all* VMs. Every VM started is managed by this server i.e. the lifetime of each VM is tied to the lifetime of this daemon.
  - The api is present at [api/server-api.yaml](./api/server-api.yaml).
  - [Code](./cmd/restserver)
- **chv-client**
  - A Golang CLI that you can use to interact with **chv-restserver** to spawn and manage VMs.
  - [Code](./cmd/client)
- Dockerfile based rootfs customization.
  - Easily add packages and binaries to your VM's rootfs by manipulating a [Dockerfile](./resources/scripts/rootfs/Dockerfile).
- Out of the box networking setup for the guest.
  - Each VM gets a tap device that gets added to a Linux bridge on the host.
  - ssh access to the VM.
- Prebuilt Linux kernel for the VMs
  - Or pass your own kernel to **chv-client** while starting VMs.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Build](#build)
  - [Build a custom rootfs for the guest](#build-a-custom-rootfs-for-the-guest)
- [Configuration](#configuration)
- [Usage](#usage)
- [Ongoing Work](#ongoing-work)
- [Contributing](#contributing)
- [License](#license)
___

## Prerequisites

- `cloud-hypervisor` only works with `/dev/kvm` for virtualization on Linux machines. Hence, we only support Linux machines.
- The [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) binary installed on the host. More on this in the [Configuration](#Configuration) section.
- Any recent host (machine you'll run the **chv-restserver** on) Linux kernel >= 2.6.
- Check if virtualization is enabled on the host by running. 
    ```bash
    stat /dev/kvm
    ```
- [Golang >= 1.23](https://go.dev/) installed on the host machine.

---

## Installation

- Install the [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) binary and note down the path of the binary. This will be used in the [Configuration](#configuration) section. By default we look for this binary at `resources/bin/cloud-hypervisor`, you may place it there.

- Download the prebuilt guest kernel for the VM from [TODO](todourl.com), note down the path. This will be used in the [Configuration](#configuration) section. By default we look for this binary at `resources/bin/vmlinux.bin`, you may place it there.

- Install Golang dependencies using -
    ```bash
    go mod tidy
    ```

---

## Build

- Make everything. You"ll be prompted by `sudo` once while making the guest rootfs.
    ```bash
    make all
    ```
  All binaries will be placed in `./out`.

- The following binaries are built -
  - **chv-restserver** - A daemon exposing a REST API to create, manage and interact with cloud-hypervisor based MicroVMs.
  - **chv-client** - A CLI client to communicate with **chv-restserver**.
  - **chv-cmdserver** - A daemon to execute shell commands that can be put inside the guest using the [Dockerfile](./resources/scripts/rootfs/Dockerfile) and **chv-rootfsmaker**.
  - **chv-codeserver** - A daemon to run **python** or **typescript** node that can be put inside the guest using the `Dockerfile` and **chv-rootfsmaker**.
  - **chv-guestinit** - The init running inside the MicroVM guest.
  - **chv-guestrootfs-ext4.img** - The rootfs used for the MicroVM guest.
  - **chv-rootfsmaker** - The program used to convert the [Dockerfile](./resources/scripts/rootfs/Dockerfile) into the guest rootfs (**chv-guestrootfs-ext4.img**).
  - `gen` - Contains the generated code for both the [cloud-hypervisor API](./api/chv-api.yaml) (used by **chv-restserver**) and [REST server API](./api/server-api.yaml) (used by **chv-client**).  

- Clean all binaries.
    ```bash
    make clean
    ```

---

## Build a custom rootfs for the guest

- The rootfs for guests can be configured using the provided [Dockerfile](./resources/scripts/rootfs/Dockerfile).

  - An example of how custom binaries can be added to the rootfs can be found [here](./resources/scripts/rootfs/Dockerfile#L66).
    - By default we keep custom binaries at `/opt/custom_scripts/` within the guest.  

- Command to make the guest rootfs -
  ```bash
  make guestrootfs
  ```

---

## Configuration

- A [config.yaml](./config.yaml) file is used to configure all the services provided by this project. It has defaults but could be modified.

- Configuring services on the host -
  - Host services are configured under the `hostservices` section.

- Configuring **chv-restserver** -
  - The `hostservices` -> `restserver` sub-section is used.
  - **state_dir** - Where each MicroVM's runtime state is stored.
  - **chv_bin** - The path to the **cloud-hypervisor** binary on the host.
  - **kernel** - The path to the kernel to be used for all MicroVMs.
  - **rootfs** - The path to the rootfs to be used for all MicroVMs. Set to **./out/chv-guestrootfs-ext4.img** by default.

- Configuring **chv-client** -
  - The `hostservices` -> `client` sub-section is used.
  - **server_host** - The IP at which the **chv-restserver** running.
  - **server_port** - The port at which the **chv-restserver** is running.

- Configuring services inside the guest -
  - Guest services are configured under the `guestservices` section.
  - The sample config file has an example for an optional **codeserver** inside the guest.

---

## Usage

- Before anything we need our `chv-restserver` to start. Start it with -
  ```bash
  sudo ./out/chv-restserver
  ```
- Root access is only needed to configure **iptables** for guest networking. Removing the root dependency is being currently worked on.

- In a separate shell we will use the CLI client to create and manage VMs.

- Start a VM named `foo`. It returns metadata about the VM which could be used to interacting with the VM.
  ```bash
  ./out/chv-client start -n foo
  started VM: {"codeServerPort":"","ip":"10.20.1.2/24","status":"RUNNING","tapDeviceName":"tap-foo","vmName":"foo"}
  ```

- SSH into the VM.
  - ssh credentials are configured [here](./resources/scripts/rootfs/Dockerfile#L6).
  ```bash
  # Use the IP returned. Password is "elara0000"
  ssh elara@10.20.1.2
  ```

- Inspecting a VM named `foo`.
  ```bash
  ./out/chv-client list -n foo
  VM: {"ip":"10.20.1.2/24","status":"RUNNING","tapDeviceName":"tap-foo","vmName":"foo"}
  ```

- List all the VMs.
  ```bash
  ./out/chv-client list-all
  VMs: {"vms":[{"ip":"10.20.1.2/24","status":"RUNNING","tapDeviceName":"tap-foo","vmName":"foo"}]}
  ```

- Stop the VM.
  ```bash
  ./out/chv-client stop -n foo
  ```

- Destroy the VM.
  ```bash
  ./out/chv-client destroy -n foo
  ```

---

## Ongoing Work

- The current focus is on a Python SDK on top of the [REST API](./api/server-api.yaml).

- This SDK could be used to provide coding and general sandboxes to LLMs or AI Agents via tool use.

---

## Contribution

First off, thank you for considering contributing to **chv-starter-pack**! 🎉

### How to Contribute

#### Reporting Bugs

If you find a bug, please [open an issue](https://github.com/yourusername/chv-starter-pack/issues/new) and include:

- A clear description of the problem
- Steps to reproduce the issue
- Expected vs. actual behavior
- Any relevant logs or screenshots

#### Suggesting Features

Have an idea for a new feature? We'd love to hear it! Please [open an issue](https://github.com/yourusername/chv-starter-pack/issues/new) and provide:

- A clear description of the feature
- The motivation behind it
- Potential benefits

#### Pull Requests

1. **Fork the Repository**

2. **Create a Feature Branch**
    ```bash
    git checkout -b feature/your-feature-name
    ```

3. **Commit Your Changes**
    ```bash
    git commit -m "Add feature: your feature description"
    ```

4. **Push to Your Fork**
    ```bash
    git push origin feature/your-feature-name
    ```

5. **Open a Pull Request**

---

## License

This project is licensed under the [MIT License](./LICENSE).

---
