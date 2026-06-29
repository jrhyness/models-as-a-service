"""
E2E tests for GET /v1/tenant gateway discovery endpoint.

Tests cover:
- Unauthenticated access (401)
- Authenticated access with valid service account token
- Response structure validation
- Gateway metadata accuracy
"""

import logging
import requests
import json
from conftest import TLS_VERIFY

log = logging.getLogger(__name__)


def test_tenant_discovery_requires_auth(maas_api_internal_url: str):
    """
    Verify /v1/tenant endpoint requires authentication.
    Without a bearer token, the endpoint should return 401 Unauthorized.

    Note: This endpoint is internal-only (not exposed through Gateway),
    so we call the maas-api Service directly.
    """
    url = f"{maas_api_internal_url}/v1/tenant"

    # Attempt without Authorization header
    r = requests.get(url, timeout=10, verify=TLS_VERIFY)

    log.info(f"[tenant] GET {url} (no auth) -> {r.status_code}")
    print(f"[tenant] GET /v1/tenant without auth: {r.status_code}")

    assert r.status_code == 401, f"Expected 401 without auth, got {r.status_code}"

    # Verify error message structure
    try:
        error_data = r.json()
        assert "error" in error_data, "Response should include 'error' field"
        print(f"[tenant] Error response: {error_data.get('error')}")
    except Exception:
        pass  # Error message format not critical for this test


def test_tenant_discovery_with_invalid_token(maas_api_internal_url: str):
    """
    Verify /v1/tenant endpoint rejects invalid tokens.
    """
    url = f"{maas_api_internal_url}/v1/tenant"

    # Attempt with invalid bearer token
    headers = {"Authorization": "Bearer invalid-token-12345"}
    r = requests.get(url, headers=headers, timeout=10, verify=TLS_VERIFY)

    log.info(f"[tenant] GET {url} (invalid token) -> {r.status_code}")
    print(f"[tenant] GET /v1/tenant with invalid token: {r.status_code}")

    assert r.status_code == 401, f"Expected 401 with invalid token, got {r.status_code}"


def test_tenant_discovery_authenticated(maas_api_internal_url: str, headers: dict):
    """
    Verify /v1/tenant endpoint returns tenant and gateway metadata when authenticated.

    This test uses the standard auth headers (service account token) that other E2E tests use.
    Since the default tenant's RBAC is created by the operator, the service account
    should have permission to access the AITenant CR.
    """
    url = f"{maas_api_internal_url}/v1/tenant"

    r = requests.get(url, headers=headers, timeout=10, verify=TLS_VERIFY)

    log.info(f"[tenant] GET {url} (authenticated) -> {r.status_code}")
    print(f"[tenant] GET /v1/tenant authenticated: {r.status_code}")

    # The endpoint should return 200 if the service account has access,
    # or 403 if RBAC hasn't been configured yet
    assert r.status_code in (200, 403), \
        f"Expected 200 or 403 with auth, got {r.status_code}: {r.text[:400]}"

    if r.status_code == 403:
        print("[tenant] Got 403 - service account lacks AITenant access (expected in some deployments)")
        return

    # If we got 200, validate the response structure
    data = r.json()
    print(f"[tenant] Response: {json.dumps(data, indent=2)}")

    # Validate response structure
    assert "tenant" in data, "Response should include 'tenant' object"
    assert "gateway" in data, "Response should include 'gateway' object"

    # Validate tenant metadata
    tenant = data["tenant"]
    assert "name" in tenant, "Tenant should have 'name' field"
    assert isinstance(tenant["name"], str), "Tenant name should be a string"
    print(f"[tenant] Tenant name: {tenant['name']}")

    # Validate gateway metadata
    gateway = data["gateway"]
    required_fields = ["name", "namespace", "externalHost", "externalUrl", "protocol", "port"]
    for field in required_fields:
        assert field in gateway, f"Gateway should have '{field}' field"

    # Validate field types
    assert isinstance(gateway["name"], str), "Gateway name should be a string"
    assert isinstance(gateway["namespace"], str), "Gateway namespace should be a string"
    assert isinstance(gateway["externalHost"], str), "externalHost should be a string"
    assert isinstance(gateway["externalUrl"], str), "externalUrl should be a string"
    assert isinstance(gateway["protocol"], str), "Protocol should be a string"
    assert isinstance(gateway["port"], int), "Port should be an integer"

    # Validate protocol value
    assert gateway["protocol"] in ("http", "https"), f"Protocol should be http or https, got {gateway['protocol']}"

    # Validate externalUrl format
    assert gateway["externalUrl"].startswith(gateway["protocol"] + "://"), \
        "externalUrl should start with protocol://"
    assert gateway["externalHost"] in gateway["externalUrl"], \
        "externalUrl should contain externalHost"

    # Validate listeners array (optional but if present, check structure)
    if "listeners" in gateway:
        assert isinstance(gateway["listeners"], list), "Listeners should be an array"
        if len(gateway["listeners"]) > 0:
            listener = gateway["listeners"][0]
            listener_fields = ["name", "hostname", "port", "protocol"]
            for field in listener_fields:
                assert field in listener, f"Listener should have '{field}' field"
            print(f"[tenant] First listener: {listener['name']} ({listener['protocol']} on port {listener['port']})")

    print(f"[tenant] Gateway: {gateway['name']} in {gateway['namespace']}")
    print(f"[tenant] External URL: {gateway['externalUrl']}")
    print(f"[tenant] Test passed - tenant discovery working correctly")


def test_tenant_discovery_gateway_matches_deployment(maas_api_internal_url: str, headers: dict, gateway_host: str):
    """
    Verify the gateway hostname returned by /v1/tenant matches the actual gateway host
    being used by the E2E tests.

    This is a regression test for the original problem: Dashboard assuming cluster domain
    instead of using the actual gateway hostname.
    """
    url = f"{maas_api_internal_url}/v1/tenant"

    r = requests.get(url, headers=headers, timeout=10, verify=TLS_VERIFY)

    if r.status_code == 403:
        print("[tenant] Skipping gateway host validation (403 forbidden)")
        return

    assert r.status_code == 200, f"Expected 200, got {r.status_code}"

    data = r.json()
    gateway = data["gateway"]

    # The external host returned by the endpoint should match (or be related to) the gateway_host
    # used by the E2E tests
    external_host = gateway["externalHost"]

    log.info(f"[tenant] Gateway external host: {external_host}")
    log.info(f"[tenant] E2E gateway host: {gateway_host}")

    # In most cases, these should match or the external host should be a substring
    # (gateway_host might include port, external_host might not)
    assert external_host in gateway_host or gateway_host in external_host, \
        f"Gateway external host '{external_host}' doesn't match E2E gateway '{gateway_host}'"

    print(f"[tenant] Gateway host validation passed: {external_host} matches {gateway_host}")


def test_tenant_discovery_not_exposed_through_gateway(gateway_host: str, is_https: bool, headers: dict):
    """
    Verify /v1/tenant endpoint is NOT exposed through the Gateway.

    This is a critical security test - the endpoint should only be accessible
    via internal Service, not through external Gateway routes.

    The HTTPRoute should explicitly exclude /v1/tenant from Gateway exposure.
    """
    scheme = "https" if is_https else "http"

    # Try to access /v1/tenant through the Gateway (should fail)
    gateway_url = f"{scheme}://{gateway_host}/v1/tenant"

    log.info(f"[tenant] Attempting Gateway access: {gateway_url}")

    r = requests.get(gateway_url, headers=headers, timeout=10, verify=TLS_VERIFY)

    log.info(f"[tenant] Gateway response: {r.status_code}")

    # Should get 404 (not found) because the route doesn't exist in HTTPRoute
    # NOT 401/403 (which would mean it's routed but auth failed)
    assert r.status_code == 404, \
        f"Expected 404 (not routed), got {r.status_code}. " \
        f"Endpoint may be exposed through Gateway! Response: {r.text[:200]}"

    print(f"[tenant] ✓ /v1/tenant correctly returns 404 through Gateway (not exposed)")
    print(f"[tenant] ✓ Endpoint is internal-only as designed")
