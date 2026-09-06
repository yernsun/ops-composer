FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash opsrunner \
    && mkdir -p /run/sshd

COPY entrypoint.sh /usr/local/bin/ops-composer-test-sshd
RUN chmod 0755 /usr/local/bin/ops-composer-test-sshd

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/ops-composer-test-sshd"]
