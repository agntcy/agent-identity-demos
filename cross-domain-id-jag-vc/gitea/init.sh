#!/bin/sh
# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# Bootstraps Gitea for the cross-domain remediation demo.
# Seeds the admin user and the target repositories.
set -eu

CONF=/data/gitea/conf/app.ini
GITEA_URL="${GITEA_INTERNAL_URL:-http://gitea:3000}"
ADMIN_USER="${GITEA_ADMIN_USER:-demo-admin}"
ADMIN_PW="${GITEA_ADMIN_PASSWORD:?GITEA_ADMIN_PASSWORD required}"
ADMIN_EMAIL="${GITEA_ADMIN_EMAIL:-admin@example.com}"

echo "[gitea-init] waiting for Gitea config at ${CONF} ..."
for i in $(seq 1 60); do
  [ -f "$CONF" ] && break
  sleep 2
done

echo "[gitea-init] ensuring admin user '${ADMIN_USER}' exists"
if gitea admin user list --config "$CONF" 2>/dev/null | awk '{print $2}' | grep -qx "$ADMIN_USER"; then
  echo "[gitea-init] admin user already present"
else
  for i in $(seq 1 5); do
    if gitea admin user create --admin --username "$ADMIN_USER" \
         --password "$ADMIN_PW" --email "$ADMIN_EMAIL" \
         --must-change-password=false --config "$CONF" 2>&1; then
      break
    fi
    echo "[gitea-init] create retry $i ..."; sleep 3
  done
fi

echo "[gitea-init] waiting for Gitea API ..."
AUTH="Authorization: Basic $(printf '%s' "${ADMIN_USER}:${ADMIN_PW}" | base64)"
for i in $(seq 1 60); do
  if wget -q -O- --header="$AUTH" "${GITEA_URL}/api/v1/version" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

seed_repo() {
  name="$1"; desc="$2"
  if wget -q -O- --header="$AUTH" "${GITEA_URL}/api/v1/repos/${ADMIN_USER}/${name}" >/dev/null 2>&1; then
    echo "[gitea-init] repo '${name}' already exists"
    return
  fi
  echo "[gitea-init] creating repo '${name}'"
  wget -q -O- --header="Content-Type: application/json" --header="$AUTH" \
    --post-data="{\"name\":\"${name}\",\"private\":false,\"auto_init\":true,\"description\":\"${desc}\"}" \
    "${GITEA_URL}/api/v1/user/repos" >/dev/null 2>&1 || echo "[gitea-init] WARN: could not create ${name}"
}

seed_file() {
  repo="$1"; path="$2"; msg="$3"; src="$4"
  if wget -q -O- --header="$AUTH" \
       "${GITEA_URL}/api/v1/repos/${ADMIN_USER}/${repo}/contents/${path}" >/dev/null 2>&1; then
    echo "[gitea-init] ${repo}/${path} already present"
    return
  fi
  # busybox base64 wraps output; the API wants one unbroken string.
  b64=$(base64 < "$src" | tr -d '\n')
  echo "[gitea-init] seeding ${repo}/${path}"
  wget -q -O- --header="Content-Type: application/json" --header="$AUTH" \
    --post-data="{\"content\":\"${b64}\",\"message\":\"${msg}\",\"branch\":\"main\"}" \
    "${GITEA_URL}/api/v1/repos/${ADMIN_USER}/${repo}/contents/${path}" >/dev/null 2>&1 \
    || echo "[gitea-init] WARN: could not seed ${path}"
}

# Target repo for sub-agent's PR (the "remediation" resource)
seed_repo "payments-service" "Payments microservice — target for CVE remediation PRs (cross-domain demo)"
# Protected repo: gateway deny-list blocks PR creation regardless of scope
seed_repo "demo-protected"   "Protected repo — deny-listed at gateway; agents cannot PR here"

# ── Analysis target ──────────────────────────────────────────────────────────
# Real source for OpenCode to analyse, so the scan step reports a weakness it
# actually found rather than a hardcoded constant.
#
# Deliberately a SOURCE-LEVEL flaw, not a vulnerable dependency: there is no
# manifest and no build, so nothing here can be resolved, fetched, compiled or
# executed, and SCA tooling has nothing to flag on this repository. The file is
# an inert fixture in a throwaway demo Gitea, in the spirit of OWASP WebGoat.
cat > /tmp/PaymentLookupRepository.java <<'JAVA'
// ─────────────────────────────────────────────────────────────────────────────
// INTENTIONALLY VULNERABLE — DEMO FIXTURE. DO NOT COPY INTO REAL CODE.
//
// Seeded by gitea-init so the AGNTCY cross-domain delegation demo has genuine
// source for the agent to analyse. This file is never built, deployed, or
// reachable by anything; it exists only to be read.
// ─────────────────────────────────────────────────────────────────────────────
package com.example.payments;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/** Looks up payment records for the payments microservice. */
public class PaymentLookupRepository {

    private final Connection connection;

    public PaymentLookupRepository(Connection connection) {
        this.connection = connection;
    }

    /** Returns every payment belonging to a customer. */
    public ResultSet findPaymentsByCustomer(String customerId) throws Exception {
        Statement statement = connection.createStatement();
        String sql = "SELECT id, amount, currency, status FROM payments "
                   + "WHERE customer_id = '" + customerId + "'";
        return statement.executeQuery(sql);
    }

    /** Free-text search over payment references. */
    public ResultSet searchByReference(String reference, String status) throws Exception {
        Statement statement = connection.createStatement();
        return statement.executeQuery(
            "SELECT * FROM payments WHERE reference LIKE '%" + reference + "%' "
          + "AND status = '" + status + "'");
    }
}
JAVA
seed_file "payments-service" "src/main/java/com/example/payments/PaymentLookupRepository.java" \
  "feat: add payment lookup repository" /tmp/PaymentLookupRepository.java

echo "[gitea-init] done."
