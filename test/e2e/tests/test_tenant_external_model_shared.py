"""E2E: one external model shared across multiple tenant gateways.

P0 scenario 2:

- One shared model attached to two supported tenant gateways has correct
  routes (one HTTPRoute per attachment, in the model namespace) and
  per-gateway status.
- Requests verify that authorization and quota consumption remain isolated:
  a user authorized in tenant A cannot call the model through tenant B's
  gateway, and exhausting tenant A's token budget does not consume tenant B's.

Shares the tenant_external_model session tenants (see conftest.tenant_external_model_tenants);
this module creates its own user namespace with unique names.

The route/status tests always run. The serving tests (auth and quota
isolation, real inference) additionally need the MaaS stack to resolve the
multi-gateway model's route, which requires the AGC's per-gateway
``status.gateways`` results: aggregate-status AGC builds write
``status.httpRouteName`` for single-attachment models only, so those tests
skip there (see ``_require_maas_route``).
"""

from __future__ import annotations

import logging
import time
import uuid

import pytest
from multitenancy_helpers import delete_namespace_best_effort, redact_sensitive
from tenant_external_model_helpers import (
    TenantExternalModelResources,
    assert_served_by_provider,
    external_model_reports_maas_route,
    gateway_ref,
    gateway_status_entry,
    infer_external_chat,
    new_admitted_user_namespace,
    provision_external_model_stack,
    serve_external_model_in_tenant,
    wait_for_attachment_httproute,
    wait_for_gateway_attachment_ready,
)

log = logging.getLogger(__name__)

pytestmark = pytest.mark.xdist_group("tenant_external_model")

# Tenant A gets a tiny budget so quota isolation is observable quickly;
# tenant B gets a large one (mirrors test_tenant_rate_limit_isolation.py).
LIMITED_TOKEN_LIMIT = 3
UNLIMITED_TOKEN_LIMIT = 100


@pytest.fixture(scope="module")
def shared_env(tenant_external_model_tenants):
    tenant_a = tenant_external_model_tenants["tenant_a"]
    tenant_b = tenant_external_model_tenants["tenant_b"]
    user_ns = new_admitted_user_namespace(
        "e2e-extmod-shr-user", tenant_a["gateway_name"], tenant_b["gateway_name"]
    )
    resources = TenantExternalModelResources()
    try:
        yield {
            "tenant_a": tenant_a,
            "tenant_b": tenant_b,
            "user_ns": user_ns,
            "resources": resources,
        }
    finally:
        resources.cleanup()
        delete_namespace_best_effort(user_ns)


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


def _wait_attachments_ready(env: dict, model: dict) -> None:
    for case in (env["tenant_a"], env["tenant_b"]):
        wait_for_gateway_attachment_ready(model["name"], model["namespace"], case["gateway_name"])


def _require_maas_route(model: dict) -> None:
    """Skip when the MaaS stack cannot resolve this multi-gateway model.

    Aggregate-status AGC builds report no per-gateway ``status.gateways``
    results and no ``status.httpRouteName`` for multi-attachment models, so
    maas-controller cannot select a route: the MaaSModelRef never reports an
    endpoint and the subscription TRLP backend stays not-ready, which makes
    per-tenant auth keys and quotas impossible to wire for the shared model.
    """
    if not external_model_reports_maas_route(model["name"], model["namespace"]):
        pytest.skip(
            "AGC reports aggregate model status only (no per-gateway status.gateways "
            "results); the MaaS stack cannot resolve a multi-gateway model's route, so "
            "per-tenant auth/quota serving for a shared model cannot be exercised"
        )


class TestSharedModelTwoGateways:
    """One model, two attachments: routes, status and serving on both."""

    @pytest.fixture(scope="class")
    def shared_model(self, shared_env):
        env = shared_env
        model = provision_external_model_stack(
            env["resources"],
            name=f"e2e-shr-shared-{uuid.uuid4().hex[:6]}",
            namespace=env["user_ns"],
            gateway_refs=[
                gateway_ref(env["tenant_a"]["gateway_name"]),
                gateway_ref(env["tenant_b"]["gateway_name"]),
            ],
        )
        _wait_attachments_ready(env, model)
        return {"model": model}

    @pytest.fixture(scope="class")
    def shared_serving(self, shared_env, shared_model):
        """Per-tenant auth/subscription stacks and API keys for the shared model."""
        env = shared_env
        model = shared_model["model"]
        _require_maas_route(model)
        access_a = _serve_in_tenant(env, env["tenant_a"], model)
        access_b = _serve_in_tenant(env, env["tenant_b"], model)
        return {"access_a": access_a, "access_b": access_b}

    def test_one_httproute_per_attachment(self, shared_env, shared_model):
        """Each attachment has its own HTTPRoute in the model namespace."""
        env = shared_env
        model = shared_model["model"]
        routes_by_gateway = {}
        for case in (env["tenant_a"], env["tenant_b"]):
            routes = wait_for_attachment_httproute(model["namespace"], case["gateway_name"])
            assert routes, f"no HTTPRoute attached to {case['gateway_name']}"
            routes_by_gateway[case["gateway_name"]] = routes
        route_uids = {
            route["metadata"]["uid"]
            for routes in routes_by_gateway.values()
            for route in routes
        }
        assert len(route_uids) == 2, (
            f"expected two distinct HTTPRoutes (one per gateway), got uids {route_uids}"
        )

    def test_per_gateway_status(self, shared_env, shared_model):
        """status.gateways carries an independent ready result per gateway."""
        env = shared_env
        model = shared_model["model"]
        if gateway_status_entry(
            model["name"], model["namespace"], env["tenant_a"]["gateway_name"]
        ) is None:
            pytest.skip(
                "AGC reports aggregate model status only (no status.gateways entries); "
                "per-gateway readiness is covered by test_both_gateways_serve"
            )
        for case in (env["tenant_a"], env["tenant_b"]):
            wait_for_gateway_attachment_ready(model["name"], model["namespace"], case["gateway_name"])

    def test_both_gateways_serve(self, shared_env, shared_model, shared_serving):
        """Real inference succeeds through both gateways with the same provider
        binding and credential."""
        env = shared_env
        model = shared_model["model"]
        for case, access in (
            (env["tenant_a"], shared_serving["access_a"]),
            (env["tenant_b"], shared_serving["access_b"]),
        ):
            response = infer_external_chat(
                case["gateway_url"], model["namespace"], model["client_name"], access["api_key"],
                path_tag=model["path_tag"],
            )
            assert_served_by_provider(response, model["path_tag"], credential=model["credential"])


class TestTenantAuthIsolation:
    """A user authorized in tenant A cannot call the model through tenant B's
    gateway (and symmetrically)."""

    @pytest.fixture(scope="class")
    def isolated_keys(self, shared_env):
        env = shared_env
        model = provision_external_model_stack(
            env["resources"],
            name=f"e2e-shr-auth-{uuid.uuid4().hex[:6]}",
            namespace=env["user_ns"],
            gateway_refs=[
                gateway_ref(env["tenant_a"]["gateway_name"]),
                gateway_ref(env["tenant_b"]["gateway_name"]),
            ],
        )
        _wait_attachments_ready(env, model)
        _require_maas_route(model)
        # Only tenant A gets a policy/subscription: its key is the authorized one.
        access_a = _serve_in_tenant(env, env["tenant_a"], model)
        return {"model": model, "key_a": access_a["api_key"]}

    def test_tenant_a_key_authorized_only_on_tenant_a_gateway(self, shared_env, isolated_keys):
        env = shared_env
        model = isolated_keys["model"]
        response = infer_external_chat(
            env["tenant_a"]["gateway_url"],
            model["namespace"],
            model["client_name"],
            isolated_keys["key_a"],
            path_tag=model["path_tag"],
        )
        assert_served_by_provider(response, model["path_tag"])

        response = infer_external_chat(
            env["tenant_b"]["gateway_url"],
            model["namespace"],
            model["client_name"],
            isolated_keys["key_a"],
            path_tag=model["path_tag"],
            retries=1,
        )
        assert response.status_code in (401, 403), (
            f"tenant A's API key must be rejected by tenant B's gateway, got "
            f"{response.status_code}: {redact_sensitive(response.text)}"
        )

    def test_unknown_key_rejected_on_both_gateways(self, shared_env, isolated_keys):
        env = shared_env
        model = isolated_keys["model"]
        for case in (env["tenant_a"], env["tenant_b"]):
            response = infer_external_chat(
                case["gateway_url"],
                model["namespace"],
                model["client_name"],
                api_key=f"sk-extmod-invalid-{uuid.uuid4().hex[:8]}",
                path_tag=model["path_tag"],
                retries=1,
            )
            assert response.status_code in (401, 403), (
                f"unknown API key must be rejected by {case['gateway_name']}, got "
                f"{response.status_code}: {redact_sensitive(response.text)}"
            )


class TestTenantQuotaIsolation:
    """Quota consumption is tracked per tenant: exhausting tenant A's token
    budget leaves tenant B's untouched."""

    @pytest.fixture(scope="class")
    def quota_model(self, shared_env):
        env = shared_env
        model = provision_external_model_stack(
            env["resources"],
            name=f"e2e-shr-quota-{uuid.uuid4().hex[:6]}",
            namespace=env["user_ns"],
            gateway_refs=[
                gateway_ref(env["tenant_a"]["gateway_name"]),
                gateway_ref(env["tenant_b"]["gateway_name"]),
            ],
        )
        _wait_attachments_ready(env, model)
        _require_maas_route(model)
        access_a = _serve_in_tenant(
            env, env["tenant_a"], model, token_limit=LIMITED_TOKEN_LIMIT, window="1m"
        )
        access_b = _serve_in_tenant(
            env, env["tenant_b"], model, token_limit=UNLIMITED_TOKEN_LIMIT, window="1m"
        )
        return {"model": model, "access_a": access_a, "access_b": access_b}

    def test_quota_exhaustion_isolated_per_tenant(self, shared_env, quota_model):
        env = shared_env
        model = quota_model["model"]

        # Drive tenant A past its budget: at least one 200 must precede the
        # 429 (a fresh budget always admits the first request — see
        # test_tenant_rate_limit_isolation._exhaust_until_429).
        successes = 0
        limited = None
        deadline = time.time() + 90
        while time.time() < deadline:
            limited = infer_external_chat(
                env["tenant_a"]["gateway_url"],
                model["namespace"],
                model["client_name"],
                quota_model["access_a"]["api_key"],
                path_tag=model["path_tag"],
            )
            if limited.status_code == 200:
                successes += 1
            elif limited.status_code == 429:
                if successes:
                    break
            else:
                raise AssertionError(
                    f"unexpected inference response on tenant A: {redact_sensitive(limited.text)}"
                )
            time.sleep(1.0)
        assert limited is not None and limited.status_code == 429, (
            f"tenant A did not hit its token budget after {successes} successes: "
            f"{redact_sensitive(limited.text if limited is not None else 'no response')}"
        )
        assert successes > 0, "tenant A hit 429 before any successful inference (limits not live?)"

        # Tenant B's budget is independent and still serves.
        response = infer_external_chat(
            env["tenant_b"]["gateway_url"],
            model["namespace"],
            model["client_name"],
            quota_model["access_b"]["api_key"],
            path_tag=model["path_tag"],
        )
        assert_served_by_provider(response, model["path_tag"], credential=model["credential"])

        # And tenant A stays limited while tenant B keeps serving.
        still_limited = infer_external_chat(
            env["tenant_a"]["gateway_url"],
            model["namespace"],
            model["client_name"],
            quota_model["access_a"]["api_key"],
            path_tag=model["path_tag"],
            retries=1,
        )
        assert still_limited.status_code == 429, (
            f"tenant A should remain rate limited, got {still_limited.status_code}: "
            f"{redact_sensitive(still_limited.text)}"
        )
        again_b = infer_external_chat(
            env["tenant_b"]["gateway_url"],
            model["namespace"],
            model["client_name"],
            quota_model["access_b"]["api_key"],
            path_tag=model["path_tag"],
        )
        assert_served_by_provider(again_b, model["path_tag"])
