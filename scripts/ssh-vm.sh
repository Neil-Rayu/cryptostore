#!/usr/bin/env bash
# SSH into the running dev VM as user dev. Extra args run as a remote command.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec ssh -i "$ROOT/build/ssh/id_ed25519" -p "${SSH_PORT:-2222}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR dev@127.0.0.1 "$@"
