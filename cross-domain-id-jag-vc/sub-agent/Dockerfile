# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Shared build contexts (compose build.additional_contexts):
#   dir_proto  → ../proto              (Directory OASF/gRPC proto tree)
#   shared_lib → ../agntcy_identity_client (Vault/CIMD/Directory client lib)
COPY --from=dir_proto . proto/
RUN python -m grpc_tools.protoc \
    -I proto \
    --python_out=. \
    --grpc_python_out=. \
    proto/agntcy/dir/core/v1/record.proto \
    proto/agntcy/dir/store/v1/store_service.proto \
    proto/agntcy/dir/search/v1/search_service.proto
COPY --from=shared_lib . agntcy_identity_client/
COPY app.py tracing.py ./
ENV PYTHONUNBUFFERED=1
EXPOSE 8300
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8300"]
