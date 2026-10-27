"""E2E: multi-provider routing lifecycle for external models (default tenant).

Scenarios from the 3.6 testing gap list ("External Models" sheet) that
exercise how a model's provider set behaves under change, all against the
header-echo endpoint (the injected credential identifies which provider
served a request; the client's path tag passes through to whichever
provider is selected):

1. Provider switching: patching a model's provider bindings A -> B -> A
   switches the serving provider without restarting the default tenant's
   ExtProc, with the surviving provider's own credential injected each time.
2. Equal-provider selection: two equally weighted providers both receive
   successful, attributed traffic over a bounded sample (an exact 50/50
   split is not required — see the assertion).
3. Partial withdrawal (issue #108): deleting one of two providers while
   requests are running keeps every request succeeding through the
   survivor, and after convergence the withdrawn provider is never
   selected again.
4. Last-provider withdrawal (issue #106): deleting the final provider
   leaves requests with no route (never a stale 200); recreating the
   provider restores serving.

These are model-level routing behaviors, not tenant behaviors, so they run
against the default tenant's gateway (GATEWAY_HOST) with uniquely named
resources in the shared model namespace — the same shape
test_external_models.py uses, minus its fixed names. The default
payload-processing stack must be praxis-extproc: the switching/withdrawal
semantics are Praxis routing-revision behaviors, so the module skips on
legacy-IPP deployments.

Not covered from the same sheet, deliberately:

- Session affinity: the ExternalModel CRD exposes no session-affinity knob
  to configure, so "affinity explicitly configured" cannot be expressed
  through the API yet. Revisit when the CRD grows the field.
- Overlay update safety (invalid digest): the routing overlay is rendered
  internally by the AGC/Praxis stack with no object the e2e layer can
  republish with a chosen digest; there is no lever to pull from here.

The withdrawal scenarios are gated on TENANT_EXTERNAL_MODEL_WITHDRAWAL_E2E
until the praxis release containing the fixes for issues #106/#108 (see
require_provider_withdrawal_support); switching and equal-selection always
run.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

import pytest
from external_model_helpers import (
    EXTERNAL_MODEL_KIND,
    EXTERNAL_PROVIDER_KIND,
    apply_credential_secret,
    apply_external_model,
    apply_external_provider,
    apply_maas_model_ref_for_external,
    assert_served_by_provider,
    external_model_binding,
    external_model_route_name,
    infer_external_chat,
    patch_external_model_provider_refs,
)
from multitenancy_helpers import (
    GATEWAY_NAMESPACE,
    LABEL_TENANT_INSTANCE,
    _oc_run,
    extproc_deployment_uses_praxis,
    make_tenant_model_accessible,
)
from tenant_external_model_helpers import (
    TENANT_EXTERNAL_MODEL_READY_TIMEOUT,
    TenantExternalModelResources,
    require_provider_withdrawal_support,
)
from test_helper import (
    MODEL_NAMESPACE,
    _create_api_key,
    _delete_cr,
    _get_cluster_token,
    _ns,
    _wait_for_httproute_accepted,
)

log = logging.getLogger(__name__)

# Default-tenant praxis ExtProc Deployment (unsuffixed) in the gateway
# namespace — the data plane whose pods provider switching must not restart.
PROCESSING_DEPLOYMENT = "payload-processing"

pytestmark = pytest.mark.xdist_group("external")

# Bounded-sample size for equal-provider selection: large enough that a
# working weighted round-robin reaches both providers with overwhelming
# probability, small enough to keep the module's runtime bounded.
EQUAL_SELECTION_SAMPLES = 20

# Background-traffic volume for partial withdrawal: enough requests span
# the provider deletion and reconvergence to catch an old gateway pod
# selecting the withdrawn provider (issue #108).
WITHDRAWAL_TRAFFIC_REQUESTS = 30

# Convergence probing: rounds of a few requests, re-sent until every
# request in a round is served by the expected provider. A round with
# errors or the wrong provider just means "not converged yet".
CONVERGENCE_REQUESTS_PER_ROUND = 4


def _subscription_ns() -> str:
    import os

    return os.environ.get("E2E_SUBSCRIPTION_NAMESPACE", _ns())


@pytest.fixture(scope="module")
def routing_env(gateway_url):
    """Default-tenant serving environment for the routing scenarios.

    Skips unless the default payload-processing stack is praxis-extproc
    (the routing-revision semantics under test are Praxis behaviors) —
    mirroring test_praxis_extproc_restart's gate.
    """
    if not extproc_deployment_uses_praxis(PROCESSING_DEPLOYMENT):
        pytest.skip(
            f"default tenant {PROCESSING_DEPLOYMENT} is not praxis-extproc; "
            "the multi-provider routing contract is not active on this dataplane"
        )
    resources = TenantExternalModelResources()
    try:
        yield {
            "gateway_url": gateway_url,
            "model_ns": MODEL_NAMESPACE,
            "subscription_ns": _subscription_ns(),
            "resources": resources,
        }
    finally:
        resources.cleanup()


def _serve(env: dict, model: dict) -> str:
    """Authorization/subscription stack for one model on the default tenant,
    returning an API key bound to its subscription."""
    make_tenant_model_accessible(
        model["name"],
        env["subscription_ns"],
        f"{model['name']}-access",
        f"{model['name']}-sub",
        model_namespace=env["model_ns"],
        model_ready_timeout=TENANT_EXTERNAL_MODEL_READY_TIMEOUT,
    )
    env["resources"].track("maasauthpolicy", f"{model['name']}-access", env["subscription_ns"])
    env["resources"].track("maassubscription", f"{model['name']}-sub", env["subscription_ns"])
    return _create_api_key(
        _get_cluster_token(),
        f"e2e-extmod-rt-{uuid.uuid4().hex[:8]}",
        f"{model['name']}-sub",
    )


def _multi_provider_model(env: dict, name: str, provider_specs: list[dict]) -> dict:
    """A model bound to N echo providers in the model namespace.

    Each provider spec is ``{"key": "a" | "b", "credential": ...}``; the
    returned dict maps each key to the provider name, credential marker and
    binding, so tests can patch the model down to any subset of providers
    and identify who served a request by the echoed credential. The client
    path tag is shared: the request path is the client's choice and reaches
    whichever provider is selected, so credentials — not paths — carry the
    attribution.
    """
    resources = env["resources"]
    namespace = env["model_ns"]
    bindings: list[dict] = []
    providers: dict[str, dict] = {}
    for spec in provider_specs:
        suffix = uuid.uuid4().hex[:6]
        provider_name = f"{name}-{spec['key']}-provider"
        secret_name = f"{provider_name}-cred"
        credential = spec.get("credential") or f"sk-extmod-rt-{spec['key']}-{suffix}"
        path_tag = f"{name}-{spec['key']}-{suffix}"
        apply_credential_secret(secret_name, namespace, credential)
        resources.track("secret", secret_name, namespace)
        apply_external_provider(provider_name, namespace, credential_secret=secret_name)
        resources.track(EXTERNAL_PROVIDER_KIND, provider_name, namespace)
        bindings.append(external_model_binding(provider_name, path_tag=path_tag))
        providers[spec["key"]] = {
            "name": provider_name,
            "secret_name": secret_name,
            "credential": credential,
            "path_tag": path_tag,
            "binding": bindings[-1],
        }

    apply_external_model(
        name,
        namespace,
        provider_name=providers[provider_specs[0]["key"]]["name"],
        path_tag=providers[provider_specs[0]["key"]]["path_tag"],
        extra_provider_refs=bindings[1:],
    )
    resources.track(EXTERNAL_MODEL_KIND, name, namespace)
    apply_maas_model_ref_for_external(name, namespace)
    resources.track("maasmodelref", name, namespace)
    _wait_for_httproute_accepted(
        external_model_route_name(name), namespace=namespace, timeout=TENANT_EXTERNAL_MODEL_READY_TIMEOUT
    )
    return {
        "name": name,
        "namespace": namespace,
        "client_name": name,
        "client_tag": f"{name}-client",
        "providers": providers,
    }


def _infer(env: dict, model: dict, api_key: str, **kwargs):
    return infer_external_chat(
        env["gateway_url"],
        model["namespace"],
        model["client_name"],
        api_key,
        path_tag=model["client_tag"],
        **kwargs,
    )


def _extproc_pod_uids() -> set[str]:
    """UIDs of the default tenant's payload-processing ExtProc pods, so
    provider switching can prove it did not restart the data plane."""
    result = _oc_run(
        [
            "get",
            "pods",
            "-n",
            GATEWAY_NAMESPACE,
            "-l",
            f"{LABEL_TENANT_INSTANCE}={PROCESSING_DEPLOYMENT}",
            "-o",
            "jsonpath={.items[*].metadata.uid}",
        ]
    )
    return {uid for uid in (result.stdout or "").split() if uid}


def _wait_for_single_provider(env: dict, model: dict, api_key: str, credential: str) -> None:
    """Probe until every request in a round is served (200, expected
    credential) by the expected provider.

    Rounds with errors or the wrong provider mean the new routing revision
    has not converged yet — including an old gateway pod still selecting a
    withdrawn provider — and are retried until the module's ready timeout;
    a permanent failure to converge fails the test.
    """

    def _round() -> bool:
        responses = []
        for _ in range(CONVERGENCE_REQUESTS_PER_ROUND):
            response = _infer(env, model, api_key)
            if response.status_code != 200:
                log.info("convergence probe: status %d (not converged)", response.status_code)
                return False
            responses.append(response)
        for response in responses:
            if credential not in response.text:
                log.info("convergence probe: served by another provider (not converged)")
                return False
        return True

    deadline = time.time() + TENANT_EXTERNAL_MODEL_READY_TIMEOUT
    while time.time() < deadline:
        if _round():
            return
        time.sleep(5)
    pytest.fail(
        f"routing did not converge to the provider with credential marker "
        f"{credential[:12]}... within {TENANT_EXTERNAL_MODEL_READY_TIMEOUT}s"
    )


# ─── Scenario 1: provider switching without ExtProc restart ─────────────────


class TestProviderSwitching:
    """Patching the provider set A -> B -> A switches the serving provider
    without restarting the default tenant's ExtProc, with the right
    credential each time."""

    @pytest.fixture(scope="class")
    def switching_model(self, routing_env):
        env = routing_env
        model = _multi_provider_model(
            env, f"e2e-rt-sw-{uuid.uuid4().hex[:6]}", [{"key": "a"}, {"key": "b"}]
        )
        api_key = _serve(env, model)
        return {"model": model, "api_key": api_key}

    def test_switch_a_to_b_to_a_without_extproc_restart(self, routing_env, switching_model):
        env = routing_env
        model = switching_model["model"]
        api_key = switching_model["api_key"]
        provider_a = model["providers"]["a"]
        provider_b = model["providers"]["b"]
        client_tag = model["client_tag"]

        # Baseline: the model serves with both providers available.
        response = _infer(env, model, api_key)
        assert_served_by_provider(response, client_tag)

        pod_uids_before = _extproc_pod_uids()
        assert pod_uids_before, "no payload-processing ExtProc pods found for the default tenant"

        # Switch to provider B only.
        patch_external_model_provider_refs(
            model["name"], model["namespace"], [provider_b["binding"]]
        )
        _wait_for_single_provider(env, model, api_key, provider_b["credential"])

        # Switch back to provider A only.
        patch_external_model_provider_refs(
            model["name"], model["namespace"], [provider_a["binding"]]
        )
        _wait_for_single_provider(env, model, api_key, provider_a["credential"])

        # The data plane was never restarted: same ExtProc pods throughout.
        assert _extproc_pod_uids() == pod_uids_before, (
            "provider switching must not restart the default tenant's ExtProc pods"
        )


# ─── Scenario 2: equal-provider selection over bounded samples ──────────────


class TestEqualProviderSelection:
    """Two equally weighted providers both receive successful, attributed
    traffic over a bounded sample.

    An exact 50/50 split is not asserted — the contract is that selection
    is not degenerate (all traffic to one provider) and that every request
    succeeds and is attributable to one of the two."""

    @pytest.fixture(scope="class")
    def equal_model(self, routing_env):
        env = routing_env
        model = _multi_provider_model(
            env, f"e2e-rt-eq-{uuid.uuid4().hex[:6]}", [{"key": "a"}, {"key": "b"}]
        )
        api_key = _serve(env, model)
        return {"model": model, "api_key": api_key}

    def test_both_providers_receive_traffic(self, routing_env, equal_model):
        env = routing_env
        model = equal_model["model"]
        api_key = equal_model["api_key"]
        credential_a = model["providers"]["a"]["credential"]
        credential_b = model["providers"]["b"]["credential"]

        counts = {"a": 0, "b": 0}
        for _ in range(EQUAL_SELECTION_SAMPLES):
            response = _infer(env, model, api_key)
            assert response.status_code == 200, (
                f"inference failed on an equally weighted two-provider model: "
                f"{response.text[:300]}"
            )
            if credential_a in response.text:
                counts["a"] += 1
            if credential_b in response.text:
                counts["b"] += 1
        assert counts["a"] > 0 and counts["b"] > 0, (
            f"equal-provider selection is degenerate over {EQUAL_SELECTION_SAMPLES} "
            f"requests: provider a served {counts['a']}, provider b served {counts['b']} "
            "(an exact 50/50 split is not required, but both must receive traffic)"
        )


# ─── Scenario 3: partial withdrawal under live traffic (issue #108) ─────────


class TestPartialWithdrawal:
    """Deleting one of two providers while requests are running keeps every
    request succeeding through the survivor; after convergence the
    withdrawn provider is never selected again."""

    @pytest.fixture(scope="class")
    def withdrawal_model(self, routing_env):
        require_provider_withdrawal_support()
        env = routing_env
        model = _multi_provider_model(
            env, f"e2e-rt-pw-{uuid.uuid4().hex[:6]}", [{"key": "a"}, {"key": "b"}]
        )
        api_key = _serve(env, model)
        return {"model": model, "api_key": api_key}

    def test_requests_survive_provider_b_removal(self, routing_env, withdrawal_model):
        env = routing_env
        model = withdrawal_model["model"]
        api_key = withdrawal_model["api_key"]
        provider_a = model["providers"]["a"]
        provider_b = model["providers"]["b"]

        results: list[tuple[int, str]] = []
        errors: list[Exception] = []

        def _traffic() -> None:
            for _ in range(WITHDRAWAL_TRAFFIC_REQUESTS):
                try:
                    response = _infer(env, model, api_key)
                    results.append((response.status_code, response.text))
                except Exception as exc:  # noqa: BLE001 - recorded, asserted below
                    errors.append(exc)
                time.sleep(1)

        thread = threading.Thread(target=_traffic)
        thread.start()
        try:
            # Delete provider B while the requests are running.
            time.sleep(2)
            _delete_cr(EXTERNAL_PROVIDER_KIND, provider_b["name"], model["namespace"])
        finally:
            thread.join()

        assert not errors, f"inference requests raised during provider withdrawal: {errors}"
        failed = [status for status, _ in results if status != 200]
        assert not failed, (
            f"requests must keep succeeding through provider A while B is withdrawn; "
            f"got statuses {failed}"
        )
        # After convergence, only A is selected — B's credential never
        # serves again, and every request still succeeds.
        _wait_for_single_provider(env, model, api_key, provider_a["credential"])


# ─── Scenario 4: last-provider withdrawal (issue #106) ──────────────────────


class TestLastProviderWithdrawal:
    """Deleting the final provider leaves requests with no route (never a
    stale 200 from the old revision); recreating the provider restores
    serving.

    The ExternalModel CRD requires at least one externalProviderRefs entry
    (minItems: 1), so "removing the final provider" is expressed by
    deleting the provider CR the model references.
    """

    @pytest.fixture(scope="class")
    def last_provider_model(self, routing_env):
        require_provider_withdrawal_support()
        env = routing_env
        model = _multi_provider_model(env, f"e2e-rt-lw-{uuid.uuid4().hex[:6]}", [{"key": "a"}])
        api_key = _serve(env, model)
        return {"model": model, "api_key": api_key}

    def test_no_route_then_restored_after_recreate(self, routing_env, last_provider_model):
        env = routing_env
        model = last_provider_model["model"]
        api_key = last_provider_model["api_key"]
        provider_a = model["providers"]["a"]
        client_tag = model["client_tag"]

        # Baseline: serving.
        response = _infer(env, model, api_key)
        assert_served_by_provider(response, client_tag, credential=provider_a["credential"])

        # Remove the final provider: the new empty routing revision must
        # serve no route. A stale 200 from the old revision is the bug
        # (issue #106); transient propagation is absorbed by the retries.
        _delete_cr(EXTERNAL_PROVIDER_KIND, provider_a["name"], model["namespace"])

        def _no_route() -> bool:
            response = _infer(env, model, api_key, retries=1)
            assert response.status_code != 200, (
                f"request must not be served after the final provider is withdrawn "
                f"(stale route), got 200: {response.text[:300]}"
            )
            return True

        deadline = time.time() + TENANT_EXTERNAL_MODEL_READY_TIMEOUT
        while True:
            try:
                _no_route()
                break
            except AssertionError:
                if time.time() >= deadline:
                    raise
                time.sleep(5)

        # Restoring the provider restores routing end to end.
        apply_external_provider(
            provider_a["name"],
            model["namespace"],
            credential_secret=provider_a["secret_name"],
        )
        _wait_for_httproute_accepted(
            external_model_route_name(model["name"]),
            namespace=model["namespace"],
            timeout=TENANT_EXTERNAL_MODEL_READY_TIMEOUT,
        )
        _wait_for_single_provider(env, model, api_key, provider_a["credential"])
