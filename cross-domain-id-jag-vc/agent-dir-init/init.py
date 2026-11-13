# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""One-shot init: push canonical OASF agent records to the Directory."""

import os
import sys
import time

import grpc
from agntcy.dir.core.v1 import record_pb2
from agntcy.dir.store.v1 import store_service_pb2_grpc
from agntcy_identity_client import directory as dir_api
from google.protobuf import struct_pb2

DIR_APISERVER_URL = os.environ.get("DIR_APISERVER_URL", "dir-apiserver:8888")
IDENTITY_NODE_URL = os.environ.get("IDENTITY_NODE_URL", "http://identity-node:4000")
AGENTS = dir_api.canonical_agent_records(IDENTITY_NODE_URL)


def wait_for_directory(max_tries=30, interval=3.0):
    """Poll until dir-apiserver accepts an RPC, not merely a TCP connection."""
    print(f"Waiting for directory at {DIR_APISERVER_URL}...")
    for i in range(max_tries):
        channel = grpc.insecure_channel(DIR_APISERVER_URL)
        try:
            stub = store_service_pb2_grpc.StoreServiceStub(channel)
            # An empty stream is side-effect free and exercises the real
            # service. UNAVAILABLE means the container has started but gRPC is
            # not ready yet.
            list(stub.Push(iter([])))
            print("Directory is ready.")
            return True
        except grpc.RpcError as exc:
            if exc.code() != grpc.StatusCode.UNAVAILABLE:
                print("Directory is ready.")
                return True
            if i < max_tries - 1:
                print(
                    f"  attempt {i+1}/{max_tries}: {exc.code().name}"
                    f" — retrying in {interval}s"
                )
                time.sleep(interval)
        except Exception as exc:
            if i < max_tries - 1:
                print(f"  attempt {i+1}/{max_tries}: {exc} — retrying in {interval}s")
                time.sleep(interval)
        finally:
            channel.close()
    print("ERROR: Directory not ready after all retries.", file=sys.stderr)
    return False


def push_agents():
    """Push all canonical OASF agent records to the Directory."""
    channel = grpc.insecure_channel(DIR_APISERVER_URL)
    try:
        stub = store_service_pb2_grpc.StoreServiceStub(channel)
        records = []
        for agent_def in AGENTS:
            data = struct_pb2.Struct()
            data.update(agent_def)
            records.append(record_pb2.Record(data=data))

        refs = list(stub.Push(iter(records)))
    finally:
        channel.close()

    for agent_def, ref in zip(AGENTS, refs):
        print(f"  ✓ {agent_def['name']} → CID: {ref.cid}")
    return refs


if __name__ == "__main__":
    if not wait_for_directory():
        sys.exit(1)
    print("Pushing canonical OASF agent records...")
    refs = push_agents()
    print(f"Done. Pushed {len(refs)} agent records.")
