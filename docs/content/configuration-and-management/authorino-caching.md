# Authorino Caching Configuration

This document describes the Authorino/Kuadrant caching configuration in MaaS, including how to tune cache TTLs for metadata and authorization evaluators.

---

## Overview

MaaS-generated AuthPolicy resources enable Authorino-style caching on:

- **Metadata evaluators** (HTTP calls to maas-api):
  - `apiKeyValidation` - validates API keys and returns user identity + groups
  - `subscription-info` - selects the appropriate subscription for the request

- **Authorization evaluators** (OPA policy evaluation):
  - `auth-valid` - validates authentication (API key OR K8s token)
  - `subscription-valid` - ensures a valid subscription was selected
  - `require-group-membership` - checks user/group membership against allowed lists

Caching reduces load on maas-api and CPU spent on Rego re-evaluation by reusing results when the cache key repeats within the TTL window.

---

## Configuration

### Environment Variables

The maas-controller deployment supports the following environment variables to configure cache TTLs:

| Variable | Description | Default | Unit | Constraints |
|----------|-------------|---------|------|-------------|
| `METADATA_CACHE_TTL` | TTL for metadata HTTP caching (apiKeyValidation, subscription-info) | `60` | seconds | Must be ≥ 0 |
| `AUTHZ_CACHE_TTL` | TTL for OPA authorization caching (auth-valid, subscription-valid, require-group-membership) | `60` | seconds | Must be ≥ 0 |

**Note:** The controller will fail to start if either TTL is set to a negative value.

### Deployment Configuration

#### Via params.env (ODH Overlay)

Edit `deployment/overlays/odh/params.env`:

```env
metadata-cache-ttl=300  # 5 minutes
authz-cache-ttl=30      # 30 seconds
```

These values are injected into the maas-controller deployment via ConfigMap.

#### Via manager.yaml (Base Deployment)

Edit `deployment/base/maas-controller/manager/manager.yaml`:

```yaml
env:
  - name: METADATA_CACHE_TTL
    value: "300"  # 5 minutes
  - name: AUTHZ_CACHE_TTL
    value: "30"   # 30 seconds
```

### Important: Authorization Cache TTL Capping

**Authorization caches are automatically capped at the metadata cache TTL** to prevent stale authorization decisions.

Authorization evaluators (auth-valid, subscription-valid, require-group-membership) depend on metadata evaluators (apiKeyValidation, subscription-info). If authorization caches outlive metadata caches, stale metadata can lead to incorrect authorization decisions.

**Example:**
```yaml
METADATA_CACHE_TTL=60   # 1 minute
AUTHZ_CACHE_TTL=300     # 5 minutes (will be capped at 60 seconds)
```

In this scenario:
- Metadata caches use 60-second TTL ✅
- Authorization caches use **60-second TTL** (capped, not 300) ✅
- A warning is logged at startup: "Authorization cache TTL exceeds metadata cache TTL"

**Recommendation:** Set `AUTHZ_CACHE_TTL ≤ METADATA_CACHE_TTL` to avoid confusion.

---

## Cache Key Design

Cache keys are carefully designed to prevent data leakage between principals, subscriptions, and models.

### Collision Resistance

Cache keys use single-character delimiters (`|` and `,`) to separate components:

- **Field delimiter**: `|` separates major components (username, groups, subscription, model)
- **Group delimiter**: `,` joins multiple group names

**Theoretical Collision Risk:**
OIDC/LDAP identities can contain arbitrary characters, including delimiter characters. This creates theoretical collision potential where crafted usernames or group names could produce identical cache keys.

**Why not use base64 or hash?**
Authorino uses CEL (Common Expression Language) for cache key construction, which does not provide:
- Base64 encoding functions
- Cryptographic hash functions (sha256, etc.)
- URL encoding functions

**Practical Impact:**
Real-world collision probability is low because:
- Most OIDC providers use standard username formats (email addresses, alphanumeric IDs)
- Collision requires crafted input with exact delimiter sequences in specific positions
- Cache entries are isolated per-model, reducing collision scope
- For Kubernetes tokens: usernames follow validated format `system:serviceaccount:namespace:sa-name` (K8s API enforces alphanumeric + hyphens only)

### Metadata Caches

**apiKeyValidation:**
- **Only runs for API key requests** (Authorization header matches `Bearer sk-oai-*`)
- Key: `<api-key-value>`
- Ensures each unique API key has its own cache entry
- Does not run for Kubernetes token requests (prevents cache pollution)

**subscription-info:**
- Key: `<username>|<groups>|<requested-subscription>|<model-namespace>/<model-name>`
- Groups joined with `,` delimiter
- Ensures cache isolation per user, group membership, requested subscription, and model

### Authorization Caches

**auth-valid:**
- Key: `<auth-type>|<identity>|<model-namespace>/<model-name>`
- For API keys: `api-key|<key-value>|model`
- For K8s tokens: `k8s-token|<username>|model`

**subscription-valid:**
- Key: Same as subscription-info metadata (ensures cache coherence)
- Format: `<username>|<groups>|<requested-subscription>|<model>`

**require-group-membership:**
- Key: `<username>|<groups>|<model-namespace>/<model-name>`
- Groups joined with `,` delimiter
- Ensures cache isolation per user identity and model

---

## Operational Tuning

### When to Increase Metadata Cache TTL

- **High API key validation load**: If maas-api is experiencing high load from repeated `/internal/v1/api-keys/validate` calls
- **Stable API keys**: API key metadata (username, groups) doesn't change frequently
- **Example**: Set `METADATA_CACHE_TTL=300` (5 minutes) to reduce maas-api load by 5x

### When to Decrease Authorization Cache TTL

- **Group membership changes**: If users are frequently added/removed from groups
- **Security compliance**: Shorter TTL ensures access changes propagate faster
- **Example**: Set `AUTHZ_CACHE_TTL=30` (30 seconds) for faster group membership updates

### Monitoring

After changing TTL values, monitor:
- **maas-api load**: Reduced `/internal/v1/api-keys/validate` and `/internal/v1/subscriptions/select` call rates
- **Authorino CPU**: Reduced OPA evaluation CPU usage
- **Request latency**: Cache hits should have lower P99 latency

---

## Security Notes

### Cache Key Correctness

All cache keys include sufficient dimensions to prevent cross-principal or cross-subscription cache sharing:

- **Never share cache entries between different users**
- **Never share cache entries between different API keys**
- **Never share cache entries between different models** (model namespace/name in key)
- **Never share cache entries between different group memberships** (groups in key)

### Cache Key Collision Risk

**Theoretical Risk:**
Cache keys use string concatenation with delimiters. OIDC/LDAP groups can contain delimiter characters (`,` or `|`), creating potential for collision.

**Example Collision Scenario:**
```
User: "alice", Groups: ["team,admin"] → "alice|team,admin|..."
User: "alice", Groups: ["team", "admin"] → "alice|team,admin|..."
```
Both produce identical cache keys despite different group membership.

**Practical Mitigation:**
- Most OIDC providers use standard formats that don't include delimiters
- For Kubernetes tokens: usernames are validated by K8s API (pattern `system:serviceaccount:namespace:sa-name`, alphanumeric + hyphens only)
- Per-model isolation limits collision scope
- Collision requires both same username AND crafted groups with delimiters in specific positions

**Known Limitations:**
- CEL (Common Expression Language) lacks base64/hash functions for cryptographic collision resistance
- Group ordering affects cache keys: `["admin", "user"]` ≠ `["user", "admin"]` (CEL has no sort function)
- Future improvements could include length-prefixing or upstream CEL enhancements

### Stale Data Window

Cache TTL represents the maximum staleness window:

- **Metadata caches**: API key revocation or group membership changes may take up to `METADATA_CACHE_TTL` seconds to propagate
- **Authorization caches**: Authorization policy changes may take up to `AUTHZ_CACHE_TTL` seconds to propagate

For immediate policy enforcement after changes:
1. Delete the affected AuthPolicy to clear Authorino's cache
2. Or wait for the TTL to expire

---

## References

- [Authorino Caching User Guide](https://docs.kuadrant.io/latest/authorino/docs/features/#caching)
- [AuthPolicy Reference](https://docs.kuadrant.io/latest/kuadrant-operator/doc/reference/authpolicy/)
- [MaaS Controller Overview](./maas-controller-overview.md)
