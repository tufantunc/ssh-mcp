#!/bin/sh
# linuxserver.io custom-cont-init hook for the integration test servers.
#
# sshd defaults to `MaxStartups 10:30:100`: beyond 10 concurrent unauthenticated
# handshakes it starts dropping connections at random. The integration suite
# runs test files in parallel and each opens real SSH connections, so it crossed
# that line as the suite grew — producing failures and, worse, *skips*, because
# a probe that gets dropped makes a test file skip itself and a degraded run
# still looks green.
#
# MaxSessions is raised for the same reason: several tests hold concurrent
# channels (sessions, SFTP) on one connection.
#
# Test fixture only — these are not production-appropriate values.
CONFIG=/config/sshd/sshd_config

if [ -f "$CONFIG" ]; then
  sed -i 's/^[#[:space:]]*MaxStartups.*/MaxStartups 100:30:200/' "$CONFIG"
  grep -q '^MaxStartups' "$CONFIG" || echo 'MaxStartups 100:30:200' >> "$CONFIG"

  sed -i 's/^[#[:space:]]*MaxSessions.*/MaxSessions 50/' "$CONFIG"
  grep -q '^MaxSessions' "$CONFIG" || echo 'MaxSessions 50' >> "$CONFIG"

  echo "[test-server-init] MaxStartups/MaxSessions raised for the integration suite"
fi
