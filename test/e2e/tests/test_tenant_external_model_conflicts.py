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

Conflict pairs share the CR name across namespaces (the client-facing name
defaults to it), which keeps the client-facing name equal to the
MaaSModelRef name: path-based inference stays authorizable that way,
because the gateway auth matches ``{namespace}/{name}`` path identities
against MaaSModelRef names. The same-named scenario instead needs distinct
client-facing names, so its serving proof is body-routed (see
assert_routed_to_echo_provider for why that proof is reachability-based).

Conflict CR names are unique per test: a previous test's models live until
module teardown, and a tenant-own model pre-holds its client-facing name
for the whole gateway — a shared name would make every later pair lose.

Shares the tenant_external_model session tenants (see conftest.tenant_external_model_tenants);
this module creates its own user namespaces with unique names.
"""

from __future__ import annotations

import logging
import time
import uuid

import pytest
from multitenancy_helpers import delete_namespace_best_effort
from tenant_external_model_helpers import (
    TenantExternalModelResources,
    assert_routed_to_echo_provider,
    assert_served_by_provider,
    destination_rules_referencing,
    gateway_ref,
    infer_bbr_chat,
    infer_external_chat,
    new_admitted_user_namespace,
    provision_external_model_stack,
    redact_sensitive,
    serve_external_model_in_tenant,
    wait_for_attachment_httproute,
    wait_for_gateway_attachment_reason,
)

log = logging.getLogger(__name__)

pytestmark = pytest.mark.xdist_group("tenant_external_model")


def _conflict_cr_name() -> str:
    """A CR name shared by one test's conflict pair, unique across tests."""
    return f"e2e-cfl-{uuid.uuid4().hex[:6]}"


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
    # Subscription and policy names must be unique within the tenant
    # namespace: same-named models in different namespaces would otherwise
    # share f"{name}-sub" and the second apply would clobber the first
    # (orphaning the first key).
    ns_suffix = model["namespace"].rsplit("-", 1)[-1]
    access = serve_external_model_in_tenant(
        case,
        model["name"],
        model["namespace"],
        policy_name=f"{model['name']}-{ns_suffix}-access",
        subscription_name=f"{model['name']}-{ns_suffix}-sub",
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
        # One shared CR name — and therefore client-facing name — across a
        # user namespace and the tenant namespace.
        name = _conflict_cr_name()

        # The older model lives in a user namespace...
        older = provision_external_model_stack(
            env["resources"],
            name=name,
            namespace=env["user_ns_1"],
            gateway_refs=[gateway],
        )
        # ...the younger model lives in the tenant's own namespace.
        tenant_own = provision_external_model_stack(
            env["resources"],
            name=name,
            namespace=tenant_a["tenant_ns"],
            gateway_refs=[gateway],
        )
        access = _serve_in_tenant(env, tenant_a, tenant_own)

        wait_for_gateway_attachment_reason(
            older["name"], older["namespace"], tenant_a["gateway_name"], "ModelNameConflict"
        )
        # The winner serves with its own credential; the loser has no
        # admitted route and its namespace is in no subscription.
        response = infer_external_chat(
            tenant_a["gateway_url"],
            tenant_own["namespace"],
            tenant_own["client_name"],
            access["api_key"],
            path_tag=tenant_own["path_tag"],
        )
        assert_served_by_provider(
            response, tenant_own["path_tag"], credential=tenant_own["credential"]
        )
        denied = infer_external_chat(
            tenant_a["gateway_url"],
            older["namespace"],
            older["client_name"],
            access["api_key"],
            path_tag=older["path_tag"],
            retries=1,
        )
        assert denied.status_code != 200, (
            f"the conflicted loser must not serve, got {denied.status_code}: "
            f"{redact_sensitive(denied.text)}"
        )

    def test_oldest_wins_when_no_tenant_own_model(self, conflicts_env):
        """With no tenant-own model, the oldest of two user-namespace models
        with the same client-facing name wins."""
        env = conflicts_env
        tenant_a = env["tenant_a"]
        gateway = gateway_ref(tenant_a["gateway_name"])
        name = _conflict_cr_name()

        oldest = provision_external_model_stack(
            env["resources"],
            name=name,
            namespace=env["user_ns_1"],
            gateway_refs=[gateway],
        )
        # Guarantee distinct creation timestamps: the AGC decides the winner
        # by creation time (then namespace/name), and "oldest wins" is the
        # behavior under test.
        time.sleep(2)
        youngest = provision_external_model_stack(
            env["resources"],
            name=name,
            namespace=env["user_ns_2"],
            gateway_refs=[gateway],
        )
        access = _serve_in_tenant(env, tenant_a, oldest)

        wait_for_gateway_attachment_reason(
            youngest["name"], youngest["namespace"], tenant_a["gateway_name"], "ModelNameConflict"
        )
        response = infer_external_chat(
            tenant_a["gateway_url"],
            oldest["namespace"],
            oldest["client_name"],
            access["api_key"],
            path_tag=oldest["path_tag"],
        )
        assert_served_by_provider(response, oldest["path_tag"], credential=oldest["credential"])
        denied = infer_external_chat(
            tenant_a["gateway_url"],
            youngest["namespace"],
            youngest["client_name"],
            access["api_key"],
            path_tag=youngest["path_tag"],
            retries=1,
        )
        assert denied.status_code != 200, (
            f"the conflicted loser must not serve, got {denied.status_code}"
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

        # Both models attach with their own admitted route...
        for model in (model_1, model_2):
            wait_for_attachment_httproute(model["namespace"], tenant_a["gateway_name"])
        # ...and both MaaS stacks complete (the subscriptions get unique
        # names per namespace — see _serve_in_tenant).
        access_1 = _serve_in_tenant(env, tenant_a, model_1)
        access_2 = _serve_in_tenant(env, tenant_a, model_2)

        # Both models serve. The client-facing names differ from the CRD
        # names, so path-based requests cannot be authorized (the gateway
        # auth matches {namespace}/{name} path identities against
        # MaaSModelRef names only): serving is proven body-routed — each
        # request must be authorized and reach the provider. If the overlay
        # stable_id collision regressed, the second model's binding would
        # break and its request would not reach any provider.
        for model, access in ((model_1, access_1), (model_2, access_2)):
            response = infer_bbr_chat(
                tenant_a["gateway_url"], model["client_name"], access["api_key"]
            )
            assert_routed_to_echo_provider(response)

        # No DestinationRule collision: each model's tenant-published rules
        # stay distinct objects.
        rules = destination_rules_referencing(shared_cr_name, tenant_a["tenant_ns"])
        rule_uids = {rule["metadata"]["uid"] for rule in rules}
        assert len(rule_uids) >= 2 or not rules, (
            f"expected distinct DestinationRules per same-named model (or none "
            f"published in the tenant namespace), got uids {rule_uids}"
        )
