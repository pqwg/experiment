# PQ WireGuard experiments

This repository contains an experimental implementation of PQ WireGuard
accompanying the submission to IEEE S&P.

**THIS IS EXPERIMENTAL ACADEMIC SOFTWARE AND NOT FIT FOR ANYTHING BUT BENCHMARKING.**

## Repository description

**(Almost) all software in this repository will need to be compiled on a recent-ish version of Linux running on x86-64.**

### `./wireguard-linux-compat`
This folder is based on the WireGuard kernel module that was available for compatibility reasons before WireGuard was included in all mainline Linux kernel versions. We have backported the latest WireGuard code to this repository, so that we can build WireGuard out-of-tree easily.

There are links to the `kems` and `rkems` folders that contain the implementations of KEMs and RKEM.<br>
WireGuard is GPLv2-licensed.

#### Upstreams:
* **WireGuard** https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/tree/drivers/net/wireguard?id=cf517ac16ad96f3953d65ea198c0b310a1ffa14f
* **WireGuard out-of-tree build scripts** https://git.zx2c4.com/wireguard-linux-compat/commit/?id=3d3c92b4711b42169137b2ddf42ed4382e2babdf

## `./wireguard-tools`
 This folder contains the userspace tools necessary to set up WireGuard. We needed to adjust the implementation for the new types of key, as well as allowing to set (very) large keys. This folder also includes KEMs as above, but the McEliece implementation needed to use the standard libc instead of be adjusted for the Kernel.

 We also made a slight adjustment to the `wg-quick` script, which now uses a Python helper script (inline) to parse the config files: the shell globs used were much too slow for McEliece public keys.

WireGuard tools are GPLv2-licensed.

  * Upstream:
    * **wireguard-tools** https://git.zx2c4.com/wireguard-tools/commit/?id=13f4ac4cb74b5a833fa7f825ba785b1e5774e84f
    * **McEliece** https://github.com/PQClean/PQClean/tree/2cc64716044832eea747234ddbffc06746ab815d/crypto_kem/mceliece460896

### `./kems`

The KEMs used in PQ WireGuard and the ML-KEM implementation used for comparison to Rebar are available in the `kems` subfolder.
These are linked into `wireguard` and `wireguard-tools`.

Benchmarks for `ml-kem` can be run through the `test_speed.c` file, which can be compiled by calling `make`.

#### Upstreams
* **ML-KEM-512**: https://github.com/PQClean/PQClean/commit/ab2623b9ef0384eae627b9c6e2880606c2997f42
* **Dagger**: https://cryptojedi.org/crypto/#pqwireguard (based on SABER from SUPERCOP, see Hülsing et al.)
* **McEliece**: https://cryptojedi.org/crypto/#pqwireguard (based on McEliece from SUPERCOP, see Hülsing et al.)
* **X25519**: Based on x25519-donna and a thin wrapper around the kernel libraries.

### `./rkems`

The WireGuard implementation always uses reinforced KEM for the client identity keys. However, for the non-Rebar instantiations we use the trivial instantiation of RKEM by combining Dagger and McEliece, or just X25519 twice.

The implementation of RKEM is based on **ML-KEM-512**: https://github.com/PQClean/PQClean/commit/ab2623b9ef0384eae627b9c6e2880606c2997f42 and can be found in the **./rkems/rkem-ml** folder.

Benchmarks for Rebar can be run through the `test_speed.c` file, which can be compiled by calling `make speed`.

### Misc

* `./resources/` helper scripts to manage the setting up of network namespaces and execution of the experiment.

* `./build.sh` Helper script that sets up and compiles `wg` and `wireguard.ko` for all experiments.

* `./run.sh` Cleans up the `experiments` folder, calls `build.sh` and then runs all experiments.

* `./full_reset.sh` a helper script that was used during development to quickly test out a particular instantiation.

* `./setup_machine.sh` a helper script that runs the below setup instructions.

## Preparing the benchmarking environment

1. Get a spot instance for cheap on AWS with AWS Linux 2023
    * e.g. `c5d.4xlarge`, something with `x86-64` because we need AVX2.
    * If you want to run this on your own machine and/or on a different version of Linux, simpily adjust the instructions below. It is strongly suggested that this machine is allowed to get crashed (we tried to eliminate memory safety problems, but that was best-effort only!). We strongly recommend using a fresh install on bare metal or a VM using hardware virtualization, and wiping the machine afterward.
    * The McEliece and Dagger implementations use AVX2 intrinsics in a way that is not allowed by the Linux kernel and may cause memory corruption that may cause problems down the line.

2. SSH to it and clone this repository.
3. Configure machine by the below steps or run `./setup_machine.sh`:

* Install dependencies
```sh
sudo dnf install -y \
    python3 zsh bash kernel-devel kernel-modules-extra \
    kernel6.12 kernel6.12-modules-extra kernel-tools tmux \
    kernel-headers iproute-tc  iptables python-unversioned-command
```
*  Set up systemctl and kernel

```sh
echo "net.core.message_cost = 0
kernel.printk_ratelimit = 0
kernel.printk_ratelimit_burst = 9999990" | sudo tee /etc/sysctl.d/10-experiment.conf

echo "blacklist wireguard
libchacha20poly1305
udp_tunnel
ip6_udp_tunnel
curve25519-x86_64" | sudo tee /etc/modules-load.d/wireguard.conf
```

* Switch to the kernel6.12 version

```sh
version=$(rpm -q --qf '%{version}-%{release}.%{arch}\n' kernel6.12 | sort -V | tail -1)
sudo grubby --set-default "/boot/vmlinuz-$version"
sudo reboot
```

6. Run `./build.sh`.

7. For the experiment that you need, go to that directory: e.g. `./experiments/pq-x25519mock`

8. Call `env EXPERIMENTS=1000 ./run.sh` and get a coffee.

**Note that `$EXPERIMENTS` sets the number of pings with 4.5s interval (triggering network traffic / VPN setup), so it does not exactly correspond to the number of WG handshakes.**

9. Find the results in the `experiments` folder

10. Call `cat dmesg.log | ./process.py out.csv` to process the results.
