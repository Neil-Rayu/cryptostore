#!/usr/bin/env bash
# Prepare a Debian 13 (trixie) cloud guest for CryptoStore development.
#
# - Downloads the "generic" qcow2 (standard kernel with 9p; the genericcloud
#   kernel lacks it), verified against Debian's SHA512SUMS, into
#   build/images/ and creates a copy-on-write overlay build/vm/disk.qcow2.
# - Generates an SSH key for the VM in build/ssh/.
# - Builds a cloud-init seed (build/vm/seed.img) that creates user dev/dev
#   (passwordless sudo), installs compiler + kernel headers + pciutils and
#   mounts driver/, tools/ and include/ under /mnt/host over virtio-9p.
# - Boots the VM once headless; cloud-init provisions it and powers it off.
#
# Re-running is safe; FORCE=1 throws away the existing VM disk.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG_DIR="$ROOT/build/images"
VM_DIR="$ROOT/build/vm"
SSH_DIR="$ROOT/build/ssh"
BASE_URL="https://cloud.debian.org/images/cloud/trixie/latest"
BASE_NAME="debian-13-generic-amd64.qcow2"
BASE="$IMG_DIR/$BASE_NAME"
DISK="$VM_DIR/disk.qcow2"
QEMU_IMG="$ROOT/build/qemu-src/build/qemu-img"
[ -x "$QEMU_IMG" ] || QEMU_IMG="$(command -v qemu-img)"

command -v cloud-localds >/dev/null || {
    echo "error: cloud-localds not found; sudo apt install cloud-image-utils" >&2
    exit 1
}

mkdir -p "$IMG_DIR" "$VM_DIR" "$SSH_DIR"

if [ ! -f "$BASE" ]; then
    echo "==> Downloading $BASE_NAME"
    curl -fL --progress-bar -o "$BASE.part" "$BASE_URL/$BASE_NAME"
    echo "==> Verifying checksum"
    want="$(curl -fsSL "$BASE_URL/SHA512SUMS" | awk -v f="$BASE_NAME" '$2 == f {print $1}')"
    have="$(sha512sum "$BASE.part" | awk '{print $1}')"
    if [ -z "$want" ] || [ "$want" != "$have" ]; then
        echo "error: SHA512 mismatch for $BASE_NAME" >&2
        exit 1
    fi
    mv "$BASE.part" "$BASE"
fi

if [ ! -f "$SSH_DIR/id_ed25519" ]; then
    ssh-keygen -q -t ed25519 -N "" -C "cryptostore-vm" -f "$SSH_DIR/id_ed25519"
fi

if [ -f "$DISK" ] && [ "${FORCE:-0}" != 1 ]; then
    echo "VM disk already exists: $DISK (FORCE=1 to recreate)"
    exit 0
fi

echo "==> Creating overlay disk"
rm -f "$DISK"
"$QEMU_IMG" create -q -f qcow2 -b "$BASE" -F qcow2 "$DISK" 16G

echo "==> Building cloud-init seed"
cat > "$VM_DIR/meta-data" <<EOF
instance-id: cryptostore-$(date +%s)
local-hostname: cryptostore-vm
EOF
cat > "$VM_DIR/user-data" <<EOF
#cloud-config
users:
  - name: dev
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
    plain_text_passwd: dev
    ssh_authorized_keys:
      - $(cat "$SSH_DIR/id_ed25519.pub")
package_update: true
packages:
  - build-essential
  - pciutils
  - python3
  - kmod
  - linux-headers-amd64
mounts:
  # Only these three directories are shared into the guest (SR-30).
  - [hostdriver, /mnt/host/driver, 9p, "trans=virtio,version=9p2000.L,msize=524288,nofail,x-systemd.automount", "0", "0"]
  - [hosttools, /mnt/host/tools, 9p, "trans=virtio,version=9p2000.L,msize=524288,nofail,x-systemd.automount", "0", "0"]
  - [hostinclude, /mnt/host/include, 9p, "trans=virtio,version=9p2000.L,msize=524288,nofail,x-systemd.automount", "0", "0"]
runcmd:
  # Headers for the running kernel (the meta package tracks the newest one)
  - apt-get install -y "linux-headers-\$(uname -r)"
power_state:
  mode: poweroff
  message: "CryptoStore guest provisioned"
  condition: true
EOF
cloud-localds "$VM_DIR/seed.img" "$VM_DIR/user-data" "$VM_DIR/meta-data"

echo "==> First boot: cloud-init provisions the guest and powers off (a few minutes)"
echo "    serial console log: $VM_DIR/serial.log"
NUM_CRYPTOSTORE=0 HEADLESS=1 TRACE= "$ROOT/scripts/run-vm.sh"

if grep -q "Cloud-init v.* finished" "$VM_DIR/serial.log"; then
    echo "Guest ready. Start it with scripts/run-vm.sh (login dev/dev)."
else
    echo "warning: did not see cloud-init finish; check $VM_DIR/serial.log" >&2
    exit 1
fi
