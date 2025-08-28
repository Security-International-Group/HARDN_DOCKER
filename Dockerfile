FROM quay.io/centos/centos:stream9

LABEL org.opencontainers.image.title="HARDN-XDR (CentOS Stream 9, FIPS/STIG)"
LABEL org.opencontainers.image.description="HARDN-XDR with FIPS crypto policy and OpenSCAP STIG content on CentOS Stream 9"
LABEL org.opencontainers.image.vendor="HARDN-XDR Project"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="1.0"

SHELL ["/bin/bash","-Eeuo","pipefail","-c"]

ENV LANG=C.UTF-8 \
    HARDN_XDR_HOME=/opt/hardn-xdr \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ARG HARDN_UID=10001
ARG HARDN_GID=10001


RUN dnf -y upgrade --refresh && \
    dnf -y install \
      --setopt=install_weak_deps=0 \
      --setopt=tsflags=nodocs \
      --nobest \
      --allowerasing \
      bash coreutils findutils grep sed gawk tar xz which \
      ca-certificates curl \
      openssl crypto-policies \
      openscap-scanner scap-security-guide \
      aide libpwquality \
      python3 python3-pip \
      shadow-utils \
    && dnf clean all


RUN update-crypto-policies --set FIPS || echo "WARN: Could not set FIPS (userland)"


RUN groupadd -g "${HARDN_GID}" -r hardn && \
    useradd  -u "${HARDN_UID}" -r -g hardn -d /home/hardn -m -s /usr/sbin/nologin hardn && \
    usermod -L hardn && chage -I -1 -m 0 -M 99999 -E -1 hardn

WORKDIR ${HARDN_XDR_HOME}


COPY --chown=root:root --chmod=0755 rhel.hardn.sh /usr/local/bin/rhel.hardn.sh
COPY --chown=root:root --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=root:root --chmod=0755 smoke_test.sh /usr/local/bin/smoke_test.sh


STOPSIGNAL SIGTERM


USER hardn
WORKDIR /home/hardn

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD /usr/local/bin/smoke_test.sh || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash","-lc","exec bash"]