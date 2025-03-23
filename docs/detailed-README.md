## Table of Contents

- [Build from source](#build-from-source)
- [Build](#build)
- [Build a custom rootfs for the guest](#build-a-custom-rootfs-for-the-guest)
- [Configuration](#configuration)
- [Usage](#usage)

---

## Build from source

- Clone the repository
    ```bash
    git clone https://github.com/abshkbh/arrakis.git
    cd arrakis
    ```

- Install Golang dependencies
    ```bash
    go mod tidy
    ```

- Install deps to build the project
    ```bash
    

- The easiest way to install prerequisite images is to use the `install-images.py` script.
    ```bash
    ./setup/install-images.py
    ```

- The following images are installed by the script above and can also be installed manually -
  
  - Install the [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) binary and note down the path of the binary. This will be used in the [Configuration](#configuration) section. By default we look for this binary at `resources/bin/cloud-hypervisor`, you may place it there.

  - Download the prebuilt guest kernel for the VM from [arrakis-images](https://github.com/abshkbh/arrakis-images/blob/main/guest/kernel/vmlinux.bin), note down the path. This will be used in the [Configuration](#configuration) section. By default we look for this binary at `resources/bin/vmlinux.bin`, you may place it there.

---

## Build

- Make everything. You"ll be prompted by `sudo` once while making the guest rootfs.
    ```bash
    make all
    ```
  All binaries will be placed in `./out`.

- The following binaries are built -
  - **arrakis-restserver** - A daemon exposing a REST API to create, manage and interact with cloud-hypervisor based MicroVMs.
  - **arrakis-client** - A CLI client to communicate with **arrakis-restserver**.
  - **arrakis-cmdserver** - A daemon to execute shell commands that can be put inside the guest using the [Dockerfile](./resources/scripts/rootfs/Dockerfile) and **arrakis-rootfsmaker**.
  - **arrakis-codeserver** - A daemon to run **python** or **typescript** node that can be put inside the guest using the `Dockerfile` and **arrakis-rootfsmaker**.
  - **arrakis-guestinit** - The init running inside the MicroVM guest.
  - **arrakis-guestrootfs-ext4.img** - The rootfs used for the MicroVM guest.
  - **arrakis-rootfsmaker** - The program used to convert the [Dockerfile](./resources/scripts/rootfs/Dockerfile) into the guest rootfs (**arrakis-guestrootfs-ext4.img**).
  - `gen` - Contains the generated code for both the [cloud-hypervisor API](./api/arrakis-api.yaml) (used by **arrakis-restserver**) and [REST server API](./api/server-api.yaml) (used by **arrakis-client**).  

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

- Configuring **arrakis-restserver** -
  - The `hostservices` -> `restserver` sub-section is used.
  - **state_dir** - Where each MicroVM's runtime state is stored.
  - **chv_bin** - The path to the **cloud-hypervisor** binary on the host.
  - **kernel** - The path to the kernel to be used for all MicroVMs.
  - **rootfs** - The path to the rootfs to be used for all MicroVMs. Set to **./out/arrakis-guestrootfs-ext4.img** by default.

- Configuring **arrakis-client** -
  - The `hostservices` -> `client` sub-section is used.
  - **server_host** - The IP at which the **arrakis-restserver** running.
  - **server_port** - The port at which the **arrakis-restserver** is running.

- Configuring services inside the guest -
  - Guest services are configured under the `guestservices` section.
  - The sample config file has an example for an optional **codeserver** inside the guest.

---

## Usage

- Before anything we need our `arrakis-restserver` to start. Start it with -
  ```bash
  sudo ./out/arrakis-restserver
  ```
- Root access is only needed to configure **iptables** for guest networking. Removing the root dependency is being currently worked on.

- In a separate shell we will use the CLI client to create and manage VMs.

- Start a VM named `foo`. It returns metadata about the VM which could be used to interacting with the VM.
  ```bash
  ./out/arrakis-client start -n foo
  ```
  
  ```bash
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
  ./out/arrakis-client list -n foo
  ```

  ```bash
  VM: {"ip":"10.20.1.2/24","status":"RUNNING","tapDeviceName":"tap-foo","vmName":"foo"}
  ```

- List all the VMs.
  ```bash
  ./out/arrakis-client list-all
  ```

  ```bash
  VMs: {"vms":[{"ip":"10.20.1.2/24","status":"RUNNING","tapDeviceName":"tap-foo","vmName":"foo"}]}
  ```

- Stop the VM.
  ```bash
  ./out/arrakis-client stop -n foo
  ```

- Destroy the VM.
  ```bash
  ./out/arrakis-client destroy -n foo
  ```

- Snapshotting and Restoring the VM.
  - We support snapshotting the VM and then using the snapshot to restore the VM. Currently, we restore the VM to use the same IP as the original VM. If you plan to restore the VM on the same host then either stop or destroy the original VM before restoring. In the future this won't be a constraint.
  ```bash
  ./out/arrakis-client snapshot -n foo-original -o foo-snapshot
  ```

  ```bash
  ./out/arrakis-client destroy -n foo-original -o foo-snapshot
  ```

  ```bash
  ./out/arrakis-client restore -n foo-original --snapshot foo-snapshot
  ```

---

## Ongoing Work

- Reduce sandbox startup time to less than 500 ms.

- Making existing coding agents work with Arrakis.

---

## Contribution

Thank you for considering contributing to **arrakis**! 🎉

Feel free to open a PR. A detailed contribution guide is going to be available soon.

## Legal Info

### Contributor License Agreement

In order for us to accept patches and other contributions from you, you need to adopt our Arrakis Contributor License Agreement (the "**CLA**"). Please drop a line at abshkbh@gmail.com to start this process.

Arrakis uses a tool called CLA Assistant to help us keep track of the CLA status of contributors. CLA Assistant will post a comment to your pull request indicating whether you have signed the CLA or not. If you have not signed the CLA, you will need to do so before we can accept your contribution. Signing the CLA would be one-time process, is valid for all future contributions to Arrakis, and can be done in under a minute by signing in with your GitHub account.


### License

By contributing to Arrakis, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE) and as commercial software.

---

## License

This project is licensed under the [GNU Affero General Public License v3.0](./LICENSE). For commercial licensing, please drop a line at abshkbh@gmail.com.

---
