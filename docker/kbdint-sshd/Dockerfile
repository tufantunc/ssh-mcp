# A server that takes passwords only through keyboard-interactive.
#
# This is how VMware ESXi ships when hardened: `PasswordAuthentication no` refuses
# the `password` method, while PAM still asks one hidden "Password: " prompt over
# keyboard-interactive. OpenSSH and PuTTY log in; a client that never offers
# keyboard-interactive (ssh2 without `tryKeyboard`) cannot. Debian rather than
# Alpine because the prompt has to come from PAM, which Debian's sshd uses by
# default. test/integration/keyboard-interactive.test.ts drives it.
FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && ssh-keygen -A

RUN useradd -m -s /bin/bash kbduser \
 && echo 'kbduser:kbdpass' | chpasswd

# A drop-in is read before the main file, and the first value sshd sees wins, so
# these override Debian's own `KbdInteractiveAuthentication no`.
RUN printf '%s\n' \
      'Port 2222' \
      'PasswordAuthentication no' \
      'KbdInteractiveAuthentication yes' \
      'UsePAM yes' \
      'MaxStartups 100:30:200' \
      'MaxSessions 50' \
      > /etc/ssh/sshd_config.d/10-kbdint.conf

EXPOSE 2222
CMD ["/usr/sbin/sshd", "-D", "-e"]
