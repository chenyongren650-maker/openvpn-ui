ARG UPSTREAM_IMAGE=zhisuan/openvpn-ui-runtime-base:0.9.5.6-current

FROM ${UPSTREAM_IMAGE} AS app-builder

ARG ALPINE_MIRROR=https://mirrors.ustc.edu.cn/alpine

RUN printf '%s\n' \
      "${ALPINE_MIRROR}/v3.21/main" \
      "${ALPINE_MIRROR}/v3.21/community" \
      > /etc/apk/repositories \
    && apk add --no-cache build-base git go

WORKDIR /src
COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build \
    -mod=vendor \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/openvpn-ui \
    .

ARG QRENCODE_REPOSITORY=https://github.com/d3vilh/qrencode.git
ARG QRENCODE_COMMIT=2abf477a839a3fe8142e2fb08be968273ad7fc16

WORKDIR /src/qrencode
RUN git init \
    && git remote add origin "${QRENCODE_REPOSITORY}" \
    && git fetch --depth=1 origin "${QRENCODE_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && CGO_ENABLED=0 GOOS=linux go build \
       -trimpath \
       -ldflags="-s -w" \
       -o /out/qrencode \
       .

FROM ${UPSTREAM_IMAGE}

ARG APP_VERSION=0.9.5.6
ARG VCS_REF=unknown
ARG UPSTREAM_IMAGE

LABEL maintainer="Mr.Philipp <d3vilh@github.com>" \
      version="${APP_VERSION}" \
      org.opencontainers.image.title="zhisuan-vpn-console" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/d3vilh/openvpn-ui" \
      org.opencontainers.image.base.name="${UPSTREAM_IMAGE}"

WORKDIR /opt
EXPOSE 8080/tcp

RUN rm -rf /opt/openvpn-ui /opt/scripts /opt/start.sh \
    && mkdir -p /opt/openvpn-ui /opt/scripts

COPY --from=app-builder /out/openvpn-ui /opt/openvpn-ui/openvpn-ui
COPY conf /opt/openvpn-ui/conf
COPY locales /opt/openvpn-ui/locales
COPY static /opt/openvpn-ui/static
COPY swagger /opt/openvpn-ui/swagger
COPY views /opt/openvpn-ui/views

COPY build/assets/start.sh /opt/start.sh
COPY build/assets/generate_ca_and_server_certs.sh /opt/scripts/generate_ca_and_server_certs.sh
COPY build/assets/genclient.sh /opt/scripts/genclient.sh
COPY build/assets/revoke.sh /opt/scripts/revoke.sh
COPY build/assets/restart.sh /opt/scripts/restart.sh
COPY build/assets/rmcert.sh /opt/scripts/rmcert.sh
COPY build/assets/remove.sh /opt/scripts/remove.sh
COPY build/assets/renew.sh /opt/scripts/renew.sh
COPY build/assets/app.conf /opt/openvpn-ui/conf/app.conf
COPY build/assets/easyrsa-tools.lib /usr/share/easy-rsa/easyrsa-tools.lib
COPY --from=app-builder /out/qrencode /opt/scripts/qrencode

RUN chmod 755 \
      /opt/start.sh \
      /opt/openvpn-ui/openvpn-ui \
      /opt/scripts/* \
      /usr/share/easy-rsa/easyrsa-tools.lib

CMD ["/opt/start.sh"]
