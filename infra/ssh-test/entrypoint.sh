#!/bin/sh
set -eu

: "${TEST_SSH_PASSWORD:?TEST_SSH_PASSWORD is required}"
printf '%s:%s\n' opsrunner "${TEST_SSH_PASSWORD}" | chpasswd
ssh-keygen -A

exec /usr/sbin/sshd -D -e \
  -o PasswordAuthentication=yes \
  -o KbdInteractiveAuthentication=no \
  -o PubkeyAuthentication=no \
  -o PermitRootLogin=no \
  -o UsePAM=no \
  -o AllowUsers=opsrunner
