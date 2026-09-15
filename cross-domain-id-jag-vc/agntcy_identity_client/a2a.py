# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Small A2A 1.0 JSON-RPC/HTTP adapter used by the demo agents.

It implements the protocol-facing pieces the synchronous demo needs:
Agent Card discovery, SendMessage, and GetTask.  Existing agent business
handlers remain the source of truth and are exposed as A2A task artifacts.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

A2A_VERSION = "1.0"
A2A_CONTENT_TYPE = "application/a2a+json"
TaskHandler = Callable[[dict[str, Any], Mapping[str, str]], Awaitable[dict[str, Any]]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def agent_card(
    *,
    name: str,
    description: str,
    interface_url: str,
    organization: str,
    version: str,
    skills: list[dict[str, Any]],
    security_schemes: dict[str, Any] | None = None,
    security_requirements: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build an A2A 1.0 AgentCard in ProtoJSON field naming."""
    return {
        "name": name,
        "description": description,
        "supportedInterfaces": [{
            "url": interface_url,
            "protocolBinding": "JSONRPC",
            "protocolVersion": A2A_VERSION,
        }],
        "provider": {
            "organization": organization,
            "url": "https://agntcy.org",
        },
        "version": version,
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "extendedAgentCard": False,
        },
        "securitySchemes": security_schemes or {},
        "securityRequirements": security_requirements or [],
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json"],
        "skills": skills,
    }


def bearer_security(scopes: list[str] | None = None) -> tuple[dict, list]:
    return (
        {
            "bearer": {
                "httpAuthSecurityScheme": {
                    "description": "OAuth 2.0 / ID-JAG bearer token",
                    "scheme": "Bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
        [{"schemes": {"bearer": {"list": list(scopes or [])}}}],
    )


def message_data(message: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(message, dict) or not message.get("messageId"):
        raise ValueError("message.messageId is required")
    parts = message.get("parts") or []
    if not parts:
        raise ValueError("message.parts must contain at least one part")
    merged: dict[str, Any] = {}
    texts: list[str] = []
    for part in parts:
        value = part.get("data")
        if isinstance(value, dict):
            merged.update(value)
        if isinstance(part.get("text"), str):
            texts.append(part["text"])
    if merged:
        return merged
    if texts:
        text = "\n".join(texts)
        try:
            decoded = json.loads(text)
            return decoded if isinstance(decoded, dict) else {"text": text}
        except json.JSONDecodeError:
            return {"text": text}
    raise ValueError("only JSON data and text parts are supported")


def response_data(response: Any) -> dict[str, Any]:
    """Normalize a FastAPI JSONResponse or dict returned by a business handler."""
    if isinstance(response, JSONResponse):
        return json.loads(response.body)
    if isinstance(response, dict):
        return response
    raise TypeError("A2A handler must return a dict or JSONResponse")


class A2AServer:
    def __init__(self, card: dict[str, Any], handler: TaskHandler):
        self.card = card
        self.handler = handler
        self.tasks: dict[str, dict[str, Any]] = {}

    async def send(self, params: dict[str, Any], headers: Mapping[str, str]) -> dict[str, Any]:
        message = params.get("message") or {}
        payload = message_data(message)
        task_id = message.get("taskId") or str(uuid.uuid4())
        context_id = message.get("contextId") or str(uuid.uuid4())
        try:
            output = await self.handler(payload, headers)
            state = "TASK_STATE_COMPLETED" if output.get("ok", True) else "TASK_STATE_FAILED"
        except Exception as exc:  # noqa: BLE001
            output = {"ok": False, "error": str(exc)}
            state = "TASK_STATE_FAILED"
        agent_message = {
            "messageId": str(uuid.uuid4()),
            "contextId": context_id,
            "taskId": task_id,
            "role": "ROLE_AGENT",
            "parts": [{"data": output, "mediaType": "application/json"}],
        }
        task = {
            "id": task_id,
            "contextId": context_id,
            "status": {"state": state, "message": agent_message, "timestamp": _now()},
            "artifacts": [{
                "artifactId": str(uuid.uuid4()),
                "name": f"{self.card['name']} result",
                "parts": [{"data": output, "mediaType": "application/json"}],
            }],
            "history": [message, agent_message],
            "metadata": {"protocolVersion": A2A_VERSION, "agent": self.card["name"]},
        }
        self.tasks[task_id] = task
        return task

    def install(self, app: FastAPI) -> None:
        async def get_card() -> JSONResponse:
            return JSONResponse(self.card)

        async def jsonrpc(request: Request) -> JSONResponse:
            request_id: Any = None
            try:
                requested_version = request.headers.get("a2a-version", "0.3")
                if requested_version != A2A_VERSION:
                    return self._rpc_error(
                        request_id,
                        -32009,
                        f"A2A version {requested_version} is not supported; use {A2A_VERSION}",
                        "VERSION_NOT_SUPPORTED",
                    )
                body = await request.json()
                request_id = body.get("id")
                if body.get("jsonrpc") != "2.0":
                    return self._rpc_error(request_id, -32600, "Invalid Request", "INVALID_REQUEST")
                method = body.get("method")
                params = body.get("params") or {}
                if method in {"SendMessage", "message/send"}:
                    task = await self.send(params, request.headers)
                    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": {"task": task}})
                if method in {"GetTask", "tasks/get"}:
                    task = self.tasks.get(params.get("id") or params.get("taskId"))
                    if task is None:
                        return self._rpc_error(request_id, -32001, "Task not found", "TASK_NOT_FOUND")
                    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": task})
                return self._rpc_error(request_id, -32601, "Method not found", "UNSUPPORTED_OPERATION")
            except ValueError as exc:
                return self._rpc_error(request_id, -32602, str(exc), "INVALID_PARAMS")
            except Exception as exc:  # noqa: BLE001
                return self._rpc_error(request_id, -32603, str(exc), "INTERNAL_ERROR")

        async def rest_send(request: Request) -> JSONResponse:
            version = request.headers.get("a2a-version")
            if version != A2A_VERSION:
                return JSONResponse(
                    {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "A2A-Version: 1.0 is required"}},
                    status_code=400,
                    media_type=A2A_CONTENT_TYPE,
                )
            task = await self.send(await request.json(), request.headers)
            return JSONResponse({"task": task}, media_type=A2A_CONTENT_TYPE)

        async def rest_get_task(task_id: str) -> JSONResponse:
            task = self.tasks.get(task_id)
            if task is None:
                return JSONResponse(
                    {"error": {"code": 404, "status": "NOT_FOUND", "message": "Task not found"}},
                    status_code=404,
                    media_type=A2A_CONTENT_TYPE,
                )
            return JSONResponse(task, media_type=A2A_CONTENT_TYPE)

        app.add_api_route(
            "/.well-known/agent-card.json", get_card, methods=["GET"],
            name=f"{self.card['name']}-agent-card",
        )
        app.add_api_route("/a2a", jsonrpc, methods=["POST"], name=f"{self.card['name']}-a2a-jsonrpc")
        app.add_api_route("/message:send", rest_send, methods=["POST"], name=f"{self.card['name']}-a2a-rest-send")
        app.add_api_route("/tasks/{task_id}", rest_get_task, methods=["GET"], name=f"{self.card['name']}-a2a-rest-get")

    @staticmethod
    def _rpc_error(request_id: Any, code: int, message: str, reason: str) -> JSONResponse:
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message,
                "data": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": reason,
                    "domain": "a2a-protocol.org",
                }],
            },
        })


async def send_message(
    client: httpx.AsyncClient,
    interface_url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    context_id: str | None = None,
    timeout: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    message = {
        "messageId": str(uuid.uuid4()),
        "role": "ROLE_USER",
        "parts": [{"data": payload, "mediaType": "application/json"}],
    }
    if context_id:
        message["contextId"] = context_id
    request_id = str(uuid.uuid4())
    response = await client.post(
        interface_url,
        headers={"A2A-Version": A2A_VERSION, **(headers or {})},
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "SendMessage",
            "params": {"message": message},
        },
        timeout=timeout,
    )
    response.raise_for_status()
    body = response.json()
    if body.get("error"):
        raise ValueError(body["error"].get("message", "A2A request failed"))
    task = (body.get("result") or {}).get("task") or {}
    artifacts = task.get("artifacts") or []
    parts = (artifacts[0].get("parts") or []) if artifacts else []
    output = parts[0].get("data") if parts else None
    if not isinstance(output, dict):
        raise ValueError("A2A response did not contain a JSON data artifact")
    return output, task


async def fetch_agent_card(client: httpx.AsyncClient, card_url: str) -> dict[str, Any]:
    response = await client.get(card_url)
    response.raise_for_status()
    card = response.json()
    interfaces = card.get("supportedInterfaces") or []
    if not any(
        item.get("protocolBinding") == "JSONRPC" and item.get("protocolVersion") == A2A_VERSION
        for item in interfaces
    ):
        raise ValueError("agent does not advertise an A2A 1.0 JSON-RPC interface")
    return card


def preferred_jsonrpc_url(card: dict[str, Any]) -> str:
    for interface in card.get("supportedInterfaces") or []:
        if interface.get("protocolBinding") == "JSONRPC" and interface.get("protocolVersion") == A2A_VERSION:
            return interface["url"]
    raise ValueError("no A2A 1.0 JSON-RPC interface in Agent Card")
