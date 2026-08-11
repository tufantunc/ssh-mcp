# A different sshd *implementation*, not just a different shell.
#
# Dropbear is what embedded targets, routers and many minimal images actually
# run. It supports a much narrower algorithm set than OpenSSH, so this is the
# only test target that exercises whether FROZEN_ALGORITHMS can still negotiate
# against something that is not OpenSSH — a frozen list that only OpenSSH
# satisfies would lock out a whole class of hosts.
#
# openssh-sftp-server is installed separately because dropbear ships no SFTP
# subsystem of its own.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache dropbear openssh-sftp-server

RUN adduser -D -s /bin/ash dropuser \
 && echo 'dropuser:droppass' | chpasswd

RUN mkdir -p /etc/dropbear \
 && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key \
 && dropbearkey -t rsa -s 3072 -f /etc/dropbear/dropbear_rsa_host_key

EXPOSE 2222
# -F foreground, -E log to stderr, -p port. Password auth stays enabled (-s
# would disable it), root login disabled (-w).
CMD ["dropbear", "-F", "-E", "-w", "-p", "2222"]
