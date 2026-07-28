# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# Keycloak A, with the keycloak-idjag-spi provider baked in (native ID-JAG
# issuance — see cross-domain-id-jag-vc/keycloak-idjag-spi and
# https://github.com/agntcy/agent-identity-demos/discussions/18).
#
# Build context is the cross-domain-id-jag-vc/ directory (not this
# subdirectory) so this Dockerfile can reach the sibling
# keycloak-idjag-spi/ Maven module — see docker-compose.yaml's
# `build: {context: ., dockerfile: keycloak-a/Dockerfile}`.

FROM maven:3-eclipse-temurin-21 AS build
WORKDIR /build
COPY keycloak-idjag-spi/pom.xml ./pom.xml
COPY keycloak-idjag-spi/src ./src
RUN mvn -B -q package

FROM quay.io/keycloak/keycloak:26.7
COPY --from=build /build/target/keycloak-idjag-spi.jar /opt/keycloak/providers/keycloak-idjag-spi.jar
RUN /opt/keycloak/bin/kc.sh build
