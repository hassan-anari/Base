"""
Tests for the ops platform node-management API.

Covers the PATCH /api/ops/nodes/{id} endpoint:

* happy path (operator/admin edits RPC URL) -> 200 + persisted change + audit
* no-op (no fields changed)               -> 400 "no fields to update"
* unauthorized (read_only role)           -> 403
* not found (bad id)                       -> 404

These run against a throwaway test database (migrate first: manage.py test).
"""

from __future__ import annotations

from custody.models import AdminActionLog
from django.test import Client, TestCase, override_settings

from ops.models import Chain, NodeEndpoint


class NodeUpdateAPITests(TestCase):
    @classmethod
    def setUpTestData(cls):
        chain, _ = Chain.objects.update_or_create(
            chain_id="BSC",
            defaults={
                "display_name": "BNB Smart Chain Testnet",
                "kind": "evm",
                "evm_chain_id": 97,
                "native_asset_key": "BNB",
                "is_testnet": True,
                "min_confirmations": 15,
                "sweep_threshold": "0.01",
                "memo_required": False,
                "enabled": True,
            },
        )
        cls.chain = chain
        cls.node = NodeEndpoint.objects.create(
            chain_id="BSC",
            name="Seed RPC",
            url="https://seed.example/chain",
            kind="rpc",
            priority=10,
            is_primary=True,
            enabled=True,
        )

    # -- helpers -----------------------------------------------------------
    def _patch(self, node_id, payload, role="admin", user="admin1"):
        return Client().patch(
            f"/api/ops/nodes/{node_id}",
            data=payload,
            content_type="application/json",
            HTTP_X_USER_ID=user,
            HTTP_X_ROLE=role,
        )

    # -- tests -------------------------------------------------------------
    @override_settings(ALLOW_DEV_STUB_AUTH=True)
    def test_happy_path_updates_and_audits(self):
        new_url = "https://edited.example/chain"
        resp = self._patch(self.node.id, {"url": new_url, "name": "Edited RPC"})
        self.assertEqual(resp.status_code, 200, resp.content)
        body = resp.json()
        self.assertEqual(body["url"], new_url)
        self.assertEqual(body["name"], "Edited RPC")

        # change persisted
        self.node.refresh_from_db()
        self.assertEqual(self.node.url, new_url)
        self.assertEqual(self.node.name, "Edited RPC")

        # audit trail written
        log = AdminActionLog.objects.filter(action_type="NODE_UPDATE").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.actor_id, "admin1")
        self.assertEqual(log.entity_id, str(self.node.id))
        self.assertIn("url", log.metadata.get("changes", {}))

    @override_settings(ALLOW_DEV_STUB_AUTH=True)
    def test_noop_returns_400(self):
        # send identical values -> no fields to update
        resp = self._patch(
            self.node.id,
            {"url": self.node.url, "name": self.node.name},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("no fields to update", resp.json().get("detail", ""))

    @override_settings(ALLOW_DEV_STUB_AUTH=True)
    def test_unauthorized_role_returns_403(self):
        resp = self._patch(
            self.node.id,
            {"url": "https://hack.example/chain"},
            role="read_only",
            user="u1",
        )
        self.assertEqual(resp.status_code, 403)

    @override_settings(ALLOW_DEV_STUB_AUTH=True)
    def test_not_found_returns_404(self):
        resp = self._patch("doesnotexistid", {"url": "https://x.example/chain"})
        self.assertEqual(resp.status_code, 404)
