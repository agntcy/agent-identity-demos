# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# Keycloak B, with the keycloak-idjag-spi provider baked in — Org B mints
# the narrowed sub-badge (Triage → Sub-Agent) natively via a real
# grant_type=token-exchange call, mirroring Keycloak A's native ID-JAG
# issuance from PR #19. The SPI jar is org-agnostic; authorization comes
# from idjag.allowed.* client attributes in org-b-realm.json.
#
# Build context is the cross-domain-id-jag-vc/ directory (not this
# subdirectory) so this Dockerfile can reach the sibling
# keycloak-idjag-spi/ Maven module — see docker-compose.yaml's
# `build: {context: ., dockerfile: keycloak-b/Dockerfile}`.

FROM maven:3-eclipse-temurin-21 AS build
WORKDIR /build
COPY keycloak-idjag-spi/pom.xml ./pom.xml
COPY keycloak-idjag-spi/src ./src
RUN mvn -B -q package

FROM quay.io/keycloak/keycloak:26.7
COPY --from=build /build/target/keycloak-idjag-spi.jar /opt/keycloak/providers/keycloak-idjag-spi.jar
RUN /opt/keycloak/bin/kc.sh build
