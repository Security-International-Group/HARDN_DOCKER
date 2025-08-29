# Use Debian 12 (Bookworm) as the base image
FROM debian:stable-slim

LABEL org.opencontainers.image.title="HARDN-XDR (Debian, STIG/CISA)"
LABEL org.opencontainers.image.description="HARDN-XDR with OpenSCAP STIG/CISA benchmark content on Debian 12"
LABEL org.opencontainers.image.vendor="HARDN-XDR Project"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="1.0"

SHELL ["/bin/bash","-Eeuo","pipefail","-c"]

ENV LANG=C.UTF-8 \
  HARDN_XDR_HOME=/opt/hardn-xdr \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV DEBIAN_FRONTEND=noninteractive

ARG HARDN_UID=10001
ARG HARDN_GID=10001


# Install packages in smaller chunks to avoid conflicts
RUN apt-get update && apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
      bash coreutils findutils grep sed gawk tar xz-utils which \
      ca-certificates curl \
      openssl \
      python3 python3-pip \
    && apt-get install -y --no-install-recommends \
      rsyslog ufw fail2ban apparmor apparmor-utils \
      lynis debsums rkhunter wget git macchanger \
    && apt-get install -y --no-install-recommends \
      apt-listbugs apt-listchanges needrestart apt-show-versions unattended-upgrades \
      acct sysstat auditd \
    && apt-get install -y --no-install-recommends \
      aide libpam-pwquality \
      || echo "Some security packages not available, continuing..." \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/sysctl.d /etc/apt/trusted.gpg.d /etc/iptables || true


RUN groupadd -g "${HARDN_GID}" -r hardn && \
    useradd  -u "${HARDN_UID}" -r -g hardn -d /home/hardn -m -s /bin/bash hardn && \
    usermod -L hardn && chage -I -1 -m 0 -M 99999 -E -1 hardn

WORKDIR ${HARDN_XDR_HOME}


COPY --chown=root:root --chmod=0755 deb.hardn.sh /usr/local/bin/deb.hardn.sh
COPY --chown=root:root --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=root:root --chmod=0755 smoke_test.sh /usr/local/bin/smoke_test.sh


STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
USER hardn
WORKDIR /home/hardn

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD /usr/local/bin/smoke_test.sh || exit 1

CMD ["/bin/bash"]