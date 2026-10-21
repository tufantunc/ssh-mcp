#!/bin/sh
# Local stand-ins for the docker-compose.yml test servers, for the OSS Scanner
# image. The scan has no Docker and no network, so the integration suite gets
# one sshd on the same ports instead of six containers.
#
#   test-servers.sh setup   build time: users, host keys, sshd config
#   test-servers.sh start   run time: start sshd and dropbear (needs root)
#
# Users and passwords match docker-compose.yml and test/integration/fixtures.ts.
# They are test fixtures for a throwaway container, nothing more.
set -eu

CONFIG=/etc/ssh/sshd_config_oss_scanner

setup() {
  ssh-keygen -A
  mkdir -p /run/sshd /etc/dropbear

  # ash for the user that stands in for the compose file's Alpine server.
  ln -sf /bin/busybox /usr/local/bin/ash
  grep -qx /usr/local/bin/ash /etc/shells || echo /usr/local/bin/ash >> /etc/shells

  # name:password:shell:sudo
  for spec in \
    admin:secret:/bin/bash:sudo \
    operator:oppass:/bin/bash:sudo \
    viewer:viewpass:/bin/bash: \
    bastion:bastionpass:/bin/bash: \
    alpineuser:alpinepass:/usr/local/bin/ash: \
    dropuser:droppass:/bin/bash:
  do
    IFS=: read -r name pass shell group <<EOF
$spec
EOF
    # -N: Debian already has a group named `operator`, so a per-user group
    # would collide with it.
    id "$name" >/dev/null 2>&1 || useradd -m -N -s "$shell" "$name"
    echo "$name:$pass" | chpasswd
    [ -n "$group" ] && usermod -aG "$group" "$name"
  done

  # 2222-2224 are ssh-admin/-viewer/-operator, 2225 ssh-bastion, 2226 ssh-alpine.
  # Any user can log in on any port; the suite only relies on the pairs it uses.
  # MaxStartups/MaxSessions as in docker/test-server-init.sh.
  cat > "$CONFIG" <<'EOF'
Port 2222
Port 2223
Port 2224
Port 2225
Port 2226
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
Subsystem sftp /usr/lib/openssh/sftp-server
MaxStartups 100:30:200
MaxSessions 50
AllowTcpForwarding no

# docker/bastion-init.sh: the bastion is the one host that forwards.
Match LocalPort 2225
  AllowTcpForwarding yes

# docker/alpine-sshd/Dockerfile accepts AI_AGENT; the others do not.
Match LocalPort 2226
  AcceptEnv AI_AGENT
EOF
  /usr/sbin/sshd -t -f "$CONFIG"
}

start() {
  # test/integration/proxy-jump.test.ts reaches its target as ssh-operator:2222,
  # a compose service name. /etc/hosts is written by the runtime, so this
  # cannot happen at build time.
  grep -q ' ssh-operator$' /etc/hosts || echo '127.0.0.1 ssh-operator' >> /etc/hosts
  pgrep -x sshd >/dev/null || /usr/sbin/sshd -f "$CONFIG"
  # ssh-dropbear, port 2227: a different sshd implementation.
  pgrep -x dropbear >/dev/null || dropbear -R -p 2227
  echo "test servers up: OpenSSH on 2222-2226, dropbear on 2227"
}

case "${1:-}" in
  setup) setup ;;
  start) start ;;
  *) echo "usage: $0 setup|start" >&2; exit 2 ;;
esac
