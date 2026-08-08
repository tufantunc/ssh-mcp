# A deliberately different target from the linuxserver test servers.
#
# Those all run Debian-ish userland with bash. This one is Alpine with busybox
# `ash` as the login shell, which is what the session protocol actually has to
# survive: `bind` is a bash builtin that does not exist here, `set -o history`
# is unsupported, and the default prompt differs. If the sentinel protocol or
# the shell priming quietly depend on bash, this is where it shows.
FROM alpine:3.20

RUN apk add --no-cache openssh-server && ssh-keygen -A

RUN adduser -D -s /bin/ash alpineuser \
 && echo 'alpineuser:alpinepass' | chpasswd

RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config \
 && printf '\nMaxStartups 100:30:200\nMaxSessions 50\n' >> /etc/ssh/sshd_config

EXPOSE 2222
CMD ["/usr/sbin/sshd", "-D", "-e"]
