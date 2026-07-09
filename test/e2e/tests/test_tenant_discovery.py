"""
E2E tests for GET /v1/tenants gateway discovery endpoint.

Tests cover:
- Unauthenticated access (401)
- Authenticated access with valid service account token
- Response structure validation
- Gateway metadata accuracy

These tests use kubectl run with curl to access the internal maas-api Service,
since /v1/tenants is not exposed through the Gateway and CI runs outside the cluster.
"""

import logging
import subprocess
import json
import os
import pytest
import requests
from conftest import TLS_VERIFY
from test_helper import INFRA_NAMESPACE

log = logging.getLogger(__name__)


def _kubectl_curl(url: str, headers: dict = None, namespace: str = None) -> tuple[int, str]:
    """
    Execute curl request from inside the cluster using kubectl run.

    Returns (status_code, response_body)
    """
    if namespace is None:
        namespace = INFRA_NAMESPACE
    curl_args = ["-sk", "-m", "10"]

    # Add headers
    if headers:
        for key, value in headers.items():
            curl_args.extend(["-H", f"{key}: {value}"])

    # Write full response (headers + body) to capture status code
    curl_args.extend(["-w", "\\nHTTP_CODE:%{http_code}", url])

    # Run curl in a pod
    cmd = [
        "kubectl", "run", f"test-curl-{os.getpid()}-{id(url)}",
        "--rm", "-i", "--restart=Never",
        "--image=curlimages/curl:latest",
        "-n", namespace,
        "--",
        "curl"
    ] + curl_args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout

        # Parse status code from footer
        if "HTTP_CODE:" in output:
            body, code_line = output.rsplit("HTTP_CODE:", 1)
            # Extract just the numeric status code (kubectl deletion message may be appended)
            # Example: "401pod \"test-curl-...\" deleted..." -> extract "401"
            import re
            match = re.search(r'(\d{3})', code_line)
            if match:
                status_code = int(match.group(1))
                return status_code, body.strip()
            else:
                log.error(f"Could not parse HTTP code from: {code_line}")
                return 0, body.strip()
        else:
            # Fallback if format is unexpected
            return 0, output
    except Exception as e:
        log.error(f"kubectl curl failed: {e}")
        return 0, str(e)


def test_tenant_discovery_requires_auth(maas_api_internal_url: str):
    """
    Verify /v1/tenants endpoint requires authentication.
    Without a bearer token, the endpoint should return 401 Unauthorized.

    Note: This endpoint is internal-only (not exposed through Gateway),
    so we use kubectl run with curl to access it from inside the cluster.
    """
    url = maas_api_internal_url + "/v1/tenants"
    namespace = INFRA_NAMESPACE

    # Comprehensive diagnostics for HTTP 0 connection failures
    import subprocess
    print(f"\n{'='*60}")
    print(f"[tenant] Pre-flight diagnostics for {namespace}/maas-api")
    print(f"{'='*60}")

    # 1. Service existence and ClusterIP
    svc_check = subprocess.run(
        ["kubectl", "get", "service", "maas-api", "-n", namespace,
         "-o", "jsonpath={.metadata.name} {.spec.clusterIP} {.spec.ports[0].port}"],
        capture_output=True, text=True, timeout=10
    )
    if svc_check.returncode != 0:
        log.error(f"[tenant] Service maas-api not found in namespace {namespace}")
        log.error(f"[tenant] kubectl stderr: {svc_check.stderr}")
        print(f"❌ Service maas-api does NOT exist in {namespace}")
    else:
        svc_info = svc_check.stdout.strip().split()
        if len(svc_info) >= 3:
            print(f"✓ Service: {svc_info[0]}")
            print(f"  ClusterIP: {svc_info[1]}")
            print(f"  Port: {svc_info[2]}")
        else:
            print(f"✓ Service exists: {svc_check.stdout.strip()}")

    # 2. Endpoints (ready Pods backing the Service)
    ep_check = subprocess.run(
        ["kubectl", "get", "endpoints", "maas-api", "-n", namespace,
         "-o", "jsonpath={.subsets[*].addresses[*].ip}"],
        capture_output=True, text=True, timeout=10
    )
    if ep_check.returncode == 0:
        endpoints = ep_check.stdout.strip()
        if endpoints:
            ep_list = endpoints.split()
            print(f"✓ Endpoints: {len(ep_list)} ready Pod(s)")
            print(f"  IPs: {', '.join(ep_list)}")
        else:
            log.error(f"[tenant] Service has ZERO endpoints - no ready Pods!")
            print(f"❌ Service has ZERO endpoints (no ready Pods backing the Service)")
            print(f"   This is the likely cause of HTTP 0 connection refused errors")
    else:
        print(f"❌ Could not get endpoints: {ep_check.stderr}")

    # 3. Pod status
    pod_check = subprocess.run(
        ["kubectl", "get", "pods", "-n", namespace, "-l", "app.kubernetes.io/name=maas-api",
         "-o", "jsonpath={range .items[*]}{.metadata.name}{'\\t'}{.status.phase}{'\\t'}{.status.conditions[?(@.type=='Ready')].status}{'\\n'}{end}"],
        capture_output=True, text=True, timeout=10
    )
    if pod_check.returncode == 0 and pod_check.stdout.strip():
        print(f"✓ Pods:")
        for line in pod_check.stdout.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) >= 3:
                pod_name, phase, ready = parts[0], parts[1], parts[2]
                status_icon = "✓" if phase == "Running" and ready == "True" else "❌"
                print(f"  {status_icon} {pod_name}: {phase}, Ready={ready}")
            else:
                print(f"  ? {line}")
    else:
        log.error(f"[tenant] No maas-api Pods found in {namespace}")
        print(f"❌ No Pods found with label app.kubernetes.io/name=maas-api")

    # 4. DNS resolution
    dns_check = subprocess.run(
        ["kubectl", "run", f"dns-test-{os.getpid()}", "--rm", "-i", "--restart=Never",
         "--image=busybox:1.36", "-n", namespace, "--",
         "nslookup", f"maas-api.{namespace}.svc.cluster.local"],
        capture_output=True, text=True, timeout=15
    )
    if dns_check.returncode == 0:
        # Extract just the IP address from nslookup output
        if "Address" in dns_check.stdout:
            print(f"✓ DNS resolves maas-api.{namespace}.svc.cluster.local")
        else:
            print(f"⚠ DNS test ran but output unclear: {dns_check.stdout[:100]}")
    else:
        log.error(f"[tenant] DNS resolution failed")
        print(f"❌ DNS resolution failed for maas-api.{namespace}.svc.cluster.local")

    print(f"{'='*60}\n")

    # Attempt without Authorization header
    status_code, body = _kubectl_curl(url, namespace=namespace)

    log.info(f"[tenant] GET {url} (no auth) -> HTTP {status_code}")
    print(f"[tenant] GET /v1/tenants without auth: HTTP {status_code}")

    if status_code == 0:
        log.error(f"[tenant] HTTP 0 indicates connection failure")
        print(f"\n❌ HTTP 0 = CONNECTION REFUSED")
        print(f"   Check the diagnostics above for the root cause:")
        print(f"   - If Service has ZERO endpoints → No ready Pods (most common)")
        print(f"   - If Pods show Ready=False → Check Pod logs and events")
        print(f"   - If DNS failed → Check CoreDNS and Service DNS records")
        print(f"   - If NetworkPolicy issues → Check policies in {namespace}")

    assert status_code == 401, f"Expected 401 without auth, got {status_code}. Check diagnostics above for HTTP 0 root cause."

    # Verify error message structure if JSON
    try:
        error_data = json.loads(body)
        if "error" in error_data:
            print(f"[tenant] Error response: {error_data.get('error')}")
    except Exception:
        pass  # Error message format not critical for this test


def test_tenant_discovery_with_invalid_token(maas_api_internal_url: str):
    """
    Verify /v1/tenants endpoint rejects invalid tokens.
    """
    url = maas_api_internal_url + "/v1/tenants"
    namespace = INFRA_NAMESPACE

    # Attempt with invalid bearer token
    headers = {"Authorization": "Bearer invalid-token-12345"}
    status_code, body = _kubectl_curl(url, headers=headers, namespace=namespace)

    log.info(f"[tenant] GET {url} (invalid token) -> HTTP {status_code}")
    print(f"[tenant] GET /v1/tenants with invalid token: HTTP {status_code}")

    assert status_code == 401, f"Expected 401 with invalid token, got {status_code}"


def test_tenant_discovery_authenticated(maas_api_internal_url: str, headers: dict):
    """
    Verify /v1/tenants endpoint returns tenant and gateway metadata when authenticated.

    This test uses the standard auth headers (service account token) that other E2E tests use.
    The endpoint uses system:authenticated authorization, so any authenticated user can access it.
    """
    # Skip test when Gateway is deployed in unsupported ClusterIP + Route mode
    ingress_mode = os.environ.get("INGRESS_MODE", "clusterip")
    if ingress_mode == "clusterip":
        pytest.skip(
            "Skipping when Gateway uses ClusterIP + OpenShift Route (unsupported configuration). "
            "This mixes incompatible routing paradigms. "
            "Gateway has no external hostname in spec.listeners, so /v1/tenants returns an error. "
            "Supported configuration: LoadBalancer service with hostname in spec.listeners."
        )

    url = maas_api_internal_url + "/v1/tenants"
    namespace = INFRA_NAMESPACE

    status_code, body = _kubectl_curl(url, headers=headers, namespace=namespace)

    log.info(f"[tenant] GET {url} (authenticated) -> HTTP {status_code}")
    print(f"[tenant] GET /v1/tenants authenticated: HTTP {status_code}")

    # The endpoint should return 200 with system:authenticated authorization
    assert status_code == 200, \
        f"Expected 200 with auth, got {status_code}: {body[:400]}"

    # Validate the response structure
    data = json.loads(body)
    print(f"[tenant] Response: {json.dumps(data, indent=2)}")

    # Validate response structure (array of tenants)
    assert "tenants" in data, "Response should include 'tenants' array"
    assert isinstance(data["tenants"], list), "Tenants should be an array"
    assert len(data["tenants"]) == 1, "Should return single tenant for this instance"

    # Validate tenant object
    tenant = data["tenants"][0]
    assert "name" in tenant, "Tenant should have 'name' field"
    assert "gateway" in tenant, "Tenant should have 'gateway' object"
    assert isinstance(tenant["name"], str), "Tenant name should be a string"
    print(f"[tenant] Tenant name: {tenant['name']}")

    # Validate gateway metadata
    gateway = tenant["gateway"]
    required_fields = ["name", "namespace", "externalUrl", "protocol", "port"]
    for field in required_fields:
        assert field in gateway, f"Gateway should have '{field}' field"

    # Validate field types
    assert isinstance(gateway["name"], str), "Gateway name should be a string"
    assert isinstance(gateway["namespace"], str), "Gateway namespace should be a string"
    assert isinstance(gateway["externalUrl"], str), "externalUrl should be a string"
    assert isinstance(gateway["protocol"], str), "Protocol should be a string"
    assert isinstance(gateway["port"], int), "Port should be an integer"

    # Validate protocol value
    assert gateway["protocol"] in ("http", "https"), f"Protocol should be http or https, got {gateway['protocol']}"

    # Validate externalUrl format
    assert gateway["externalUrl"].startswith(gateway["protocol"] + "://"), \
        "externalUrl should start with protocol://"

    print(f"[tenant] Gateway: {gateway['name']} in {gateway['namespace']}")
    print(f"[tenant] External URL: {gateway['externalUrl']}")
    print(f"[tenant] Test passed - tenant discovery working correctly")


def test_tenant_discovery_gateway_matches_deployment(maas_api_internal_url: str, headers: dict, gateway_host: str):
    """
    Verify the gateway URL returned by /v1/tenants matches the actual gateway host
    being used by the E2E tests.

    This is a regression test for the original problem: Dashboard assuming cluster domain
    instead of using the actual gateway hostname.

    Note: This test is skipped when the Gateway is deployed with ClusterIP service
    and OpenShift Route. This configuration is not supported - it mixes incompatible
    routing paradigms (OpenShift Routes with Gateway API). In this mode, the Gateway
    has no external hostname configured in spec.listeners, so /v1/tenants returns an
    error. The supported configuration is LoadBalancer service with hostname in spec.listeners.
    """
    # Skip test when Gateway is deployed in unsupported ClusterIP + Route mode
    ingress_mode = os.environ.get("INGRESS_MODE", "clusterip")
    if ingress_mode == "clusterip":
        pytest.skip(
            "Skipping when Gateway uses ClusterIP + OpenShift Route (unsupported configuration). "
            "This mixes incompatible routing paradigms. "
            "Gateway has no external hostname in spec.listeners, so /v1/tenants returns an error. "
            "Supported configuration: LoadBalancer service with hostname in spec.listeners."
        )

    url = maas_api_internal_url + "/v1/tenants"
    namespace = INFRA_NAMESPACE

    status_code, body = _kubectl_curl(url, headers=headers, namespace=namespace)

    assert status_code == 200, f"Expected 200, got {status_code}"

    data = json.loads(body)
    tenant = data["tenants"][0]
    gateway = tenant["gateway"]

    # The external URL should contain the gateway_host
    external_url = gateway["externalUrl"]

    log.info(f"[tenant] Gateway external URL: {external_url}")
    log.info(f"[tenant] E2E gateway host: {gateway_host}")

    # Extract hostname from externalUrl and compare with gateway_host
    assert gateway_host in external_url, \
        f"Gateway external URL '{external_url}' doesn't contain E2E gateway host '{gateway_host}'"

    print(f"[tenant] Gateway host validation passed: {external_url} contains {gateway_host}")


def test_tenant_discovery_not_exposed_through_gateway(gateway_host: str, is_https: bool, headers: dict):
    """
    Verify /v1/tenants endpoint is NOT exposed through the Gateway.

    This is a critical security test - the endpoint should only be accessible
    via internal Service, not through external Gateway routes.

    The HTTPRoute should explicitly exclude /v1/tenants from Gateway exposure.
    """
    scheme = "https" if is_https else "http"

    # Try to access /v1/tenants through the Gateway (should fail)
    gateway_url = f"{scheme}://{gateway_host}/v1/tenants"

    log.info(f"[tenant] Attempting Gateway access: {gateway_url}")

    r = requests.get(gateway_url, headers=headers, timeout=10, verify=TLS_VERIFY)

    log.info(f"[tenant] Gateway response: {r.status_code}")

    # Should get 404 (not found) because the route doesn't exist in HTTPRoute
    # NOT 401/403 (which would mean it's routed but auth failed)
    assert r.status_code == 404, \
        f"Expected 404 (not routed), got {r.status_code}. " \
        f"Endpoint may be exposed through Gateway! Response: {r.text[:200]}"

    print(f"[tenant] ✓ /v1/tenants correctly returns 404 through Gateway (not exposed)")
    print(f"[tenant] ✓ Endpoint is internal-only as designed")
