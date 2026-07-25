# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

ARG BOE_COMPOSER_IMAGE=ghcr.io/tetratelabs/built-on-envoy/composer:0.11.0-dev@sha256:842fca7db63af7385478380bf097c6e85eb16db7158a88778d6f2018b265d84f
ARG ENVOY_IMAGE=envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb

FROM ${BOE_COMPOSER_IMAGE} AS built_on_envoy

FROM ${ENVOY_IMAGE}

COPY --from=built_on_envoy /libcomposer.so /var/boe/extensions/libcomposer.so
COPY envoy.yaml /etc/envoy/envoy.yaml
COPY policies/ /etc/envoy/policies/

ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/var/boe/extensions
ENV GODEBUG=cgocheck=0

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--service-cluster", "cd-envoy-org-b"]
