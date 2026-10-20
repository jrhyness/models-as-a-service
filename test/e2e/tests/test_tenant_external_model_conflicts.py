"""E2E: model-name conflicts and same-named objects across namespaces.

P0 scenarios:

7. Two ExternalModels with the same client-facing modelName attached to one
   gateway from different namespaces: the tenant's own model always wins,
   otherwise the oldest; requests reach only the winner's provider and the
   loser reports ModelNameConflict.
8. Same-named ExternalModels and ExternalProviders in two user namespaces
   attached to one gateway both serve correctly, with no overlay stable_id or
   DestinationRule collision (regression coverage for the shared-provider
   overlay collision bug).

Shares the tenant_external_model session tenants (see conftest.tenant_external_model_tenants);
this module creates its own user namespaces with unique names.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from multitenancy_helpers import delete_namespace_best_effort
from tenant_external_model_helpers import (
    TenantExternalModelResources,
    assert_served_by_provider,
    destination_rules_referencing,
    gateway_ref,
    infer_bbr_chat,
    infer_external_chat,
    new_admitted_user_namespace,
    provision_external_model_stack,
    serve_external_model_in_tenant,
    wait_for_gateway_attachment_reason,
)

log = logging.getLogger(__name__)

pytestmark = pytest.mark.xdist_group("tenant_external_model")

CONFLICT_MODEL_NAME = "e2e-extmod-conflicted-model"


@pytest.fixture(scope="module")
def conflicts_env(tenant_external_model_tenants):
    tenant_a = tenant_external_model_tenants["tenant_a"]
    user_ns_1 = new_admitted_user_namespace("e2e-extmod-cfl-1", tenant_a["gateway_name"])
    user_ns_2 = new_admitted_user_namespace("e2e-extmod-cfl-2", tenant_a["gateway_name"])
    resources = TenantExternalModelResources()
    try:
        yield {
            "tenant_a": tenant_a,
            "user_ns_1": user_ns_1,
            "user_ns_2": user_ns_2,
            "resources": resources,
        }
    finally:
        resources.cleanup()
        delete_namespace_best_effort(user_ns_1)
        delete_namespace_best_effort(user_ns_2)


def _serve_in_tenant(env: dict, case: dict, model: dict, **kwargs) -> dict:
    access = serve_external_model_in_tenant(
        case,
        model["name"],
        model["namespace"],
        policy_name=f"{model['name']}-access",
        subscription_name=f"{model['name']}-sub",
        **kwargs,
    )
    env["resources"].track("maasauthpolicy", access["policy"], case["tenant_ns"])
    env["resources"].track("maassubscription", access["subscription"], case["tenant_ns"])
    return access


class TestModelNameConflict:
    """Same client-facing modelName on one gateway from two namespaces."""

    def test_tenant_own_model_wins_over_older_user_namespace_model(self, conflicts_env):
        """The tenant's own model wins even when a user-namespace model with
        the same client-facing name is older; the loser reports
        ModelNameConflict and never receives traffic."""
        env = conflicts_env
        tenant_a = env["tenant_a"]
        gateway = gateway_ref(tenant_a["gateway_name"])

        # The older model lives in a user namespace...
        older = provision_external_model_stack(
            env["resources"],
            name=f"e2e-cfl-old-{uuid.uuid4().hex[:6]}",
            namespace=env["user_ns_1"],
            gateway_refs=[gateway],
            model_name=CONFLICT_MODEL_NAME,
        )
        # ...the younger model lives in the tenant's own namespace.
        tenant_own = provision_external_model_stack(
            env["resources"],
            name=f"e2e-cfl-own-{uuid.uuid4().hex[:6]}",
            namespace=tenant_a["tenant_ns"],
            gateway_refs=[gateway],
            model_name=CONFLICT_MODEL_NAME,
        )
        access = _serve_in_tenant(env, tenant_a, tenant_own)

        wait_for_gateway_attachment_reason(
            older["name"], older["namespace"], tenant_a["gateway_name"], "ModelNameConflict"
        )
        response = infer_bbr_chat(tenant_a["gateway_url"], CONFLICT_MODEL_NAME, access["api_key"])
        assert_served_by_provider(
            response, tenant_own["path_tag"], credential=tenant_own["credential"]
        )
        assert older["path_tag"] not in response.text, (
            "the losing (older, user-namespace) model must not receive traffic"
        )

    def test_oldest_wins_when_no_tenant_own_model(self, conflicts_env):
        """With no tenant-own model, the oldest of two user-namespace models
        with the same client-facing name wins."""
        env = conflicts_env
        tenant_a = env["tenant_a"]
        gateway = gateway_ref(tenant_a["gateway_name"])

        oldest = provision_external_model_stack(
            env["resources"],
            name=f"e2e-cfl-a-{uuid.uuid4().hex[:6]}",
            namespace=env["user_ns_1"],
            gateway_refs=[gateway],
            model_name=CONFLICT_MODEL_NAME,
        )
        youngest = provision_external_model_stack(
            env["resources"],
            name=f"e2e-cfl-b-{uuid.uuid4().hex[:6]}",
            namespace=env["user_ns_2"],
            gateway_refs=[gateway],
            model_name=CONFLICT_MODEL_NAME,
        )
        access = _serve_in_tenant(env, tenant_a, oldest)

        wait_for_gateway_attachment_reason(
            youngest["name"], youngest["namespace"], tenant_a["gateway_name"], "ModelNameConflict"
        )
        response = infer_bbr_chat(tenant_a["gateway_url"], CONFLICT_MODEL_NAME, access["api_key"])
        assert_served_by_provider(response, oldest["path_tag"], credential=oldest["credential"])
        assert youngest["path_tag"] not in response.text, (
            "the losing (younger) model must not receive traffic"
        )


class TestSameNamedObjectsTwoNamespaces:
    """Same-named ExternalModels/Providers/Secrets in two user namespaces on
    one gateway both serve (overlay collision regression)."""

    def test_same_named_objects_both_serve(self, conflicts_env):
        env = conflicts_env
        tenant_a = env["tenant_a"]
        gateway = gateway_ref(tenant_a["gateway_name"])
        shared_cr_name = f"e2e-cfl-same-{uuid.uuid4().hex[:6]}"
        shared_secret_name = f"{shared_cr_name}-provider-cred"

        # Identical CR and Secret names in both namespaces; distinct
        # client-facing modelNames (a shared client name would be the
        # ModelNameConflict scenario instead), credentials and echo path tags
        # prove which object served.
        model_1 = provision_external_model_stack(
            env["resources"],
            name=shared_cr_name,
            namespace=env["user_ns_1"],
            gateway_refs=[gateway],
            model_name=f"{shared_cr_name}-one",
            provider_name=shared_cr_name,
            credential_secret_name=shared_secret_name,
        )
        model_2 = provision_external_model_stack(
            env["resources"],
            name=shared_cr_name,
            namespace=env["user_ns_2"],
            gateway_refs=[gateway],
            model_name=f"{shared_cr_name}-two",
            provider_name=shared_cr_name,
            credential_secret_name=shared_secret_name,
        )
        assert model_1["credential"] != model_2["credential"]
        assert model_1["path_tag"] != model_2["path_tag"]

        access_1 = _serve_in_tenant(env, tenant_a, model_1)
        access_2 = _serve_in_tenant(env, tenant_a, model_2)

        # Both models must serve through their own provider.
        response_1 = infer_external_chat(
            tenant_a["gateway_url"],
            model_1["namespace"],
            model_1["client_name"],
            access_1["api_key"],
        )
        assert_served_by_provider(
            response_1, model_1["path_tag"], credential=model_1["credential"]
        )
        response_2 = infer_external_chat(
            tenant_a["gateway_url"],
            model_2["namespace"],
            model_2["client_name"],
            access_2["api_key"],
        )
        assert_served_by_provider(
            response_2, model_2["path_tag"], credential=model_2["credential"]
        )

        # No DestinationRule collision: each model's tenant-published rules
        # stay distinct objects.
        rules = destination_rules_referencing(shared_cr_name, tenant_a["tenant_ns"])
        rule_uids = {rule["metadata"]["uid"] for rule in rules}
        assert len(rule_uids) >= 2 or not rules, (
            f"expected distinct DestinationRules per same-named model (or none "
            f"published in the tenant namespace), got uids {rule_uids}"
        )
