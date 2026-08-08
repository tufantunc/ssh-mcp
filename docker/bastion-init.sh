#!/bin/sh
# linuxserver.io custom-cont-init hook.
#
# The base openssh-server image ships AllowTcpForwarding no, which makes
# direct-tcpip channels (what ProxyJump / `profile.via` uses) fail with
# "Channel open failure: open failed". This host exists purely so the
# integration suite can exercise the bastion path against a real sshd.
#
# Test fixture only — do not model a production bastion on this.
CONFIG=/config/sshd/sshd_config

if [ -f "$CONFIG" ]; then
  sed -i 's/^[#[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding yes/' "$CONFIG"
  grep -q '^AllowTcpForwarding yes' "$CONFIG" || echo 'AllowTcpForwarding yes' >> "$CONFIG"
  echo "[bastion-init] AllowTcpForwarding enabled for ProxyJump tests"
fi
