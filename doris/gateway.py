"""Calls to outside services, all through the Sprites connector gateway.

No API key exists in this code or on the Sprite: the gateway recognises the
calling Sprite and attaches the stored credential. Connector IDs are not
secrets (they are useless outside a Sprite the policy allows).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

GATEWAY = "https://api.sprites.dev/v1/gateway"

CONNECTORS = {
    "agentmail": os.environ.get("DORIS_AGENTMAIL", "agentmail/Z-qKSX_PzzNud4FO3iIvXA"),
    "deepseek": os.environ.get("DORIS_DEEPSEEK", "custom_api/VRPrYkHmKZ6HILznRLwLBw"),
    "pinecone": os.environ.get("DORIS_PINECONE", "pinecone/12xSl_vx05vXPfaFy5feMg"),
    "box": os.environ.get("DORIS_BOX", "box/6XfQ8yQYDbdfhV2kgsmKoA"),
    "trapdoor": os.environ.get("DORIS_TRAPDOOR", ""),  # custom_api -> the trap's door
}


class GatewayError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"gateway {status}: {body[:300]}")
        self.status = status
        self.body = body


def call(service: str, method: str, path: str, body=None, timeout: float = 60,
         raw: bool = False, headers: dict | None = None):
    conn = CONNECTORS[service]
    if not conn:
        raise GatewayError(0, f"connector for {service} not configured")
    url = f"{GATEWAY}/{conn}{path}"
    data = None
    hdrs = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        else:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
    except urllib.error.HTTPError as e:
        raise GatewayError(e.code, e.read().decode("utf-8", "replace")) from None
    if raw:
        return payload
    return json.loads(payload) if payload else None
