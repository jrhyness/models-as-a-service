"""
Subscription Deletion API Key Revocation E2E Tests
==================================================

Tests that API keys are automatically revoked when a MaaSSubscription is deleted.

This is a security feature (RHOAIENG-72792) to prevent orphaned keys from
granting access if a subscription is recreated with the same name.
"""

import logging

import requests

from conftest import TLS_VERIFY
from test_helper import (
    MODEL_NAMESPACE,
    TIMEOUT,
    _apply_cr,
    _delete_cr,
    _wait_reconcile,
)

log = logging.getLogger(__name__)


class TestSubscriptionDeletionRevokesKeys:
    """Test that API keys are revoked when subscription is deleted."""

    def test_subscription_deletion_revokes_keys(self, api_keys_base_url: str, headers: dict):
        """When a MaaSSubscription is deleted, keys bound to it are revoked."""
        sub_a_name = "e2e-revoke-sub-a"
        sub_b_name = "e2e-revoke-sub-b"

        key_ids_a, key_ids_b, keys_a, keys_b = [], [], [], []

        try:
            # Create two subscriptions
            for sub_name in [sub_a_name, sub_b_name]:
                _apply_cr({
                    "apiVersion": "maas.opendatahub.io/v1alpha1",
                    "kind": "MaaSSubscription",
                    "metadata": {"name": sub_name, "namespace": MODEL_NAMESPACE},
                    "spec": {"allowedUsers": ["*"], "priority": 5},
                })
            log.info(f"Created subscriptions {sub_a_name}, {sub_b_name}")
            _wait_reconcile()

            # Create API keys for each subscription
            for i in range(2):
                r_a = requests.post(
                    api_keys_base_url,
                    headers=headers,
                    json={"name": f"e2e-revoketest-a-{i}", "subscription": sub_a_name},
                    timeout=TIMEOUT,
                    verify=TLS_VERIFY,
                )
                assert r_a.status_code in (200, 201), f"Failed to create key for sub-a: {r_a.text}"
                data_a = r_a.json()
                key_ids_a.append(data_a["id"])
                keys_a.append(data_a["key"])

                r_b = requests.post(
                    api_keys_base_url,
                    headers=headers,
                    json={"name": f"e2e-revoketest-b-{i}", "subscription": sub_b_name},
                    timeout=TIMEOUT,
                    verify=TLS_VERIFY,
                )
                assert r_b.status_code in (200, 201), f"Failed to create key for sub-b: {r_b.text}"
                data_b = r_b.json()
                key_ids_b.append(data_b["id"])
                keys_b.append(data_b["key"])

            # Verify all keys validate
            validate_url = f"{api_keys_base_url}/validate"
            for key in keys_a + keys_b:
                r = requests.post(validate_url, headers={"X-API-Key": key}, timeout=TIMEOUT, verify=TLS_VERIFY)
                assert r.status_code == 200, f"Key validation failed: {r.status_code}"
            log.info("All keys validated ✓")

            # Delete sub-a
            _delete_cr("maassubscription", sub_a_name, namespace=MODEL_NAMESPACE)
            log.info(f"Deleted subscription {sub_a_name}")
            _wait_reconcile()

            # Verify sub-a keys are revoked
            for key in keys_a:
                r = requests.post(validate_url, headers={"X-API-Key": key}, timeout=TIMEOUT, verify=TLS_VERIFY)
                assert r.status_code == 401, f"Key should be revoked but got {r.status_code}"
            log.info(f"Sub-a keys revoked ✓")

            # Verify sub-b keys still work
            for key in keys_b:
                r = requests.post(validate_url, headers={"X-API-Key": key}, timeout=TIMEOUT, verify=TLS_VERIFY)
                assert r.status_code == 200, f"Sub-b key should work but got {r.status_code}"
            log.info(f"Sub-b keys still active ✓")

        finally:
            for kid in key_ids_b:
                try:
                    requests.delete(f"{api_keys_base_url}/{kid}", headers=headers, timeout=TIMEOUT, verify=TLS_VERIFY)
                except Exception as e:
                    log.warning(f"Cleanup failed for key {kid}: {e}")
            try:
                _delete_cr("maassubscription", sub_b_name, namespace=MODEL_NAMESPACE)
            except Exception as e:
                log.warning(f"Cleanup failed for subscription {sub_b_name}: {e}")
            _wait_reconcile()

    def test_subscription_deletion_with_no_keys(self):
        """Deleting a subscription with no API keys should succeed."""
        sub_name = "e2e-revoke-nokeys"

        try:
            _apply_cr({
                "apiVersion": "maas.opendatahub.io/v1alpha1",
                "kind": "MaaSSubscription",
                "metadata": {"name": sub_name, "namespace": MODEL_NAMESPACE},
                "spec": {"allowedUsers": ["*"], "priority": 5},
            })
            _wait_reconcile()

            _delete_cr("maassubscription", sub_name, namespace=MODEL_NAMESPACE)
            _wait_reconcile()
            log.info("Subscription with no keys deleted successfully ✓")

        except Exception as e:
            log.error(f"Deletion failed: {e}")
            try:
                _delete_cr("maassubscription", sub_name, namespace=MODEL_NAMESPACE)
            except:
                pass
            raise
