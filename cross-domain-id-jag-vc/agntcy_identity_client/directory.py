# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""AGNTCY Directory Node client — OASF record push + search over gRPC.

The generated protobuf modules (agntcy.dir.*) are compiled at image build
time from the shared proto/ tree (see the consumers' Dockerfiles); imports
happen lazily so this module can be imported in environments without them.

gRPC calls are synchronous — async callers should wrap them in an executor,
e.g. `await asyncio.get_event_loop().run_in_executor(None, fn)`.
Extracted from webapp/app.py.
"""

from __future__ import annotations

OASF_SCHEMA_VERSION = "1.1.0"


def push_record(dir_apiserver_url: str, record_dict: dict) -> str:
    """Push one OASF record to the Directory. Returns its CID."""
    import grpc
    from agntcy.dir.core.v1 import record_pb2
    from agntcy.dir.store.v1 import store_service_pb2_grpc
    from google.protobuf import struct_pb2

    record_data = struct_pb2.Struct()
    record_data.update(record_dict)
    record = record_pb2.Record(data=record_data)

    channel = grpc.insecure_channel(dir_apiserver_url)
    try:
        stub = store_service_pb2_grpc.StoreServiceStub(channel)
        refs = list(stub.Push(iter([record])))
    finally:
        channel.close()
    return refs[0].cid if refs else ""


def search_by_name(dir_apiserver_url: str, agent_name: str, limit: int = 5) -> list[dict]:
    """Search Directory records by agent name. Returns raw record dicts."""
    import grpc
    from agntcy.dir.search.v1 import search_service_pb2, search_service_pb2_grpc
    from google.protobuf.json_format import MessageToDict

    req = search_service_pb2.SearchRecordsRequest(
        queries=[search_service_pb2.RecordQuery(
            type=search_service_pb2.RECORD_QUERY_TYPE_NAME,
            value=agent_name,
        )],
        limit=limit,
    )

    channel = grpc.insecure_channel(dir_apiserver_url)
    try:
        stub = search_service_pb2_grpc.SearchServiceStub(channel)
        results = list(stub.SearchRecords(req))
    finally:
        channel.close()
    return [MessageToDict(res.record.data) for res in results]
