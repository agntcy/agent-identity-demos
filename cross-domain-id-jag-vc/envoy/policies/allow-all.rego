# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

package envoy.authz

# Milestone 1 proves that the Built On Envoy OPA dynamic module loads and
# participates in both proxy paths. Delegation enforcement is introduced in
# Milestone 2; until then every request is deliberately allowed.
default allow := true
