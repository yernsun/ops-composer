#!/bin/sh
set -eu

: "${TEST_SSH_PASSWORD:?TEST_SSH_PASSWORD is required}"
: "${TEST_SSH_KEY_PASSPHRASE:?TEST_SSH_KEY_PASSPHRASE is required}"
printf '%s:%s\n' opsrunner "${TEST_SSH_PASSWORD}" | chpasswd
ssh-keygen -A

rm -f /fixture/id_ed25519 /fixture/id_ed25519.pub
ssh-keygen -q -t ed25519 -N "${TEST_SSH_KEY_PASSPHRASE}" -f /fixture/id_ed25519
install -d -m 0700 -o opsrunner -g opsrunner /home/opsrunner/.ssh
install -m 0600 -o opsrunner -g opsrunner \
  /fixture/id_ed25519.pub /home/opsrunner/.ssh/authorized_keys
chown 10001:10001 /fixture/id_ed25519
chmod 0600 /fixture/id_ed25519

exec /usr/sbin/sshd -D -e \
  -o PasswordAuthentication=yes \
  -o KbdInteractiveAuthentication=no \
  -o PubkeyAuthentication=yes \
  -o PermitRootLogin=no \
  -o UsePAM=no \
  -o AllowUsers=opsrunner
