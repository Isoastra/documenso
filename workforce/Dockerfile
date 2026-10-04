FROM documenso/documenso@sha256:1377ba20181d4d029e768b7b7615e4e49c39450a85588a525e78dc586dd2569c
USER root
COPY native.mjs patch-runtime.mjs /app/workforce/
COPY vendor/isoastra-fleet-scim-0.1.0.tgz /app/workforce/vendor.tgz
RUN mkdir -p /app/node_modules/@isoastra/fleet-scim && tar -xzf /app/workforce/vendor.tgz --strip-components=1 -C /app/node_modules/@isoastra/fleet-scim && node /app/workforce/patch-runtime.mjs /app/apps/remix/build/server

USER nodejs
