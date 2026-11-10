# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
FROM alpine:3.24
RUN apk add --no-cache openssl
COPY init.sh /init.sh
ENTRYPOINT ["sh", "/init.sh"]
