FROM kong:3.9.3

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        openssl \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY kong/plugins/hrms-auth \
     /usr/local/share/lua/5.1/kong/plugins/hrms-auth

ENV KONG_PLUGINS=bundled,hrms-auth

ENV KONG_LUA_SSL_TRUSTED_CERTIFICATE=system

ENV KONG_LUA_SSL_VERIFY_DEPTH=5