import unittest

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from agntcy_identity_client import a2a
    HAS_FASTAPI = True
except ModuleNotFoundError:
    HAS_FASTAPI = False


@unittest.skipUnless(HAS_FASTAPI, "FastAPI is installed in the service images")
class A2AAdapterTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()

        async def handler(payload, headers):
            return {"ok": True, "echo": payload, "authorization": headers.get("authorization", "")}

        self.server = a2a.A2AServer(
            a2a.agent_card(
                name="Test Agent",
                description="A test A2A agent",
                interface_url="http://testserver/a2a",
                organization="Test Org",
                version="1.0.0",
                skills=[{
                    "id": "echo",
                    "name": "Echo",
                    "description": "Echo JSON data",
                    "tags": ["test"],
                }],
            ),
            handler,
        )
        self.server.install(app)
        self.client = TestClient(app)

    def test_agent_card_and_send_message(self):
        card = self.client.get("/.well-known/agent-card.json").json()
        self.assertEqual(card["supportedInterfaces"][0]["protocolVersion"], "1.0")
        response = self.client.post(
            "/a2a",
            headers={"A2A-Version": "1.0", "Authorization": "Bearer token"},
            json={
                "jsonrpc": "2.0",
                "id": "request-1",
                "method": "SendMessage",
                "params": {
                    "message": {
                        "messageId": "message-1",
                        "role": "ROLE_USER",
                        "parts": [{"data": {"repo": "org/repo"}, "mediaType": "application/json"}],
                    }
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        task = response.json()["result"]["task"]
        self.assertEqual(task["status"]["state"], "TASK_STATE_COMPLETED")
        result = task["artifacts"][0]["parts"][0]["data"]
        self.assertEqual(result["echo"]["repo"], "org/repo")
        self.assertEqual(result["authorization"], "Bearer token")

        fetched = self.client.post(
            "/a2a",
            headers={"A2A-Version": "1.0"},
            json={
                "jsonrpc": "2.0",
                "id": "request-2",
                "method": "GetTask",
                "params": {"id": task["id"]},
            },
        ).json()["result"]
        self.assertEqual(fetched["id"], task["id"])

    def test_version_is_enforced(self):
        response = self.client.post(
            "/a2a",
            headers={"A2A-Version": "9.9"},
            json={"jsonrpc": "2.0", "id": "bad", "method": "SendMessage", "params": {}},
        )
        self.assertEqual(response.json()["error"]["data"][0]["reason"], "VERSION_NOT_SUPPORTED")


if __name__ == "__main__":
    unittest.main()
