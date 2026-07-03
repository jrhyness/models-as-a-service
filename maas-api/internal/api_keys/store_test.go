package api_keys_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/api_keys"
	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/logger"
)

func createTestStore(t *testing.T) api_keys.MetadataStore {
	t.Helper()
	return api_keys.NewMockStore()
}

// TestStore tests legacy Add() method - NOTE: This method is DEPRECATED
// Legacy SA tokens are not stored in database in production - they use Kubernetes TokenReview
// These tests are kept for backward compatibility testing only.
func TestStore(t *testing.T) {
	t.Skip("Legacy Add() method is deprecated - SA tokens are not stored in database")

	// Tests removed - legacy SA token storage is not used in practice
	// Only hash-based keys (AddKey) are stored in database
}

func TestStoreValidation(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	t.Run("TokenNotFound", func(t *testing.T) {
		_, err := store.Get(ctx, "nonexistent-jti")
		require.Error(t, err)
		assert.Equal(t, api_keys.ErrKeyNotFound, err)
	})

	// Legacy Add() validation tests removed - method is deprecated
	// SA tokens are not stored in database, validated via Kubernetes instead
}

func TestPostgresStoreFromURL(t *testing.T) {
	ctx := context.Background()
	testLogger := logger.Development()

	t.Run("InvalidURL", func(t *testing.T) {
		_, err := api_keys.NewPostgresStoreFromURL(ctx, testLogger, "mysql://localhost:3306/db", "test-tenant")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid database URL")
	})

	t.Run("EmptyURL", func(t *testing.T) {
		_, err := api_keys.NewPostgresStoreFromURL(ctx, testLogger, "", "test-tenant")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid database URL")
	})
}

func TestRevokeAllForTenant(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	// Add keys for tenant-a
	err := store.AddKey(ctx, "alice", "key-tenant-a-1", "hash-a1", "Alice Key 1", "", []string{"users"}, "sub-a", "tenant-a", nil, false)
	require.NoError(t, err)
	err = store.AddKey(ctx, "bob", "key-tenant-a-2", "hash-a2", "Bob Key 1", "", []string{"users"}, "sub-a", "tenant-a", nil, false)
	require.NoError(t, err)

	// Add keys for tenant-b (should not be affected)
	err = store.AddKey(ctx, "charlie", "key-tenant-b-1", "hash-b1", "Charlie Key 1", "", []string{"users"}, "sub-b", "tenant-b", nil, false)
	require.NoError(t, err)

	t.Run("RevokeAllForTenant_Success", func(t *testing.T) {
		count, err := store.RevokeAllForTenant(ctx, "tenant-a")
		require.NoError(t, err)
		assert.Equal(t, 2, count, "should revoke 2 keys for tenant-a")

		// Verify tenant-a keys are revoked
		_, err = store.GetByHash(ctx, "hash-a1")
		require.ErrorIs(t, err, api_keys.ErrInvalidKey, "tenant-a key should be revoked")
		_, err = store.GetByHash(ctx, "hash-a2")
		require.ErrorIs(t, err, api_keys.ErrInvalidKey, "tenant-a key should be revoked")

		// Verify tenant-b key is still active
		key, err := store.GetByHash(ctx, "hash-b1")
		require.NoError(t, err)
		assert.Equal(t, "Charlie Key 1", key.Name, "tenant-b key should still be active")
	})

	t.Run("RevokeAllForTenant_NoKeys", func(t *testing.T) {
		count, err := store.RevokeAllForTenant(ctx, "tenant-c")
		require.NoError(t, err)
		assert.Equal(t, 0, count, "should return 0 when no keys exist for tenant")
	})

	t.Run("RevokeAllForTenant_AlreadyRevoked", func(t *testing.T) {
		// tenant-a keys already revoked above
		count, err := store.RevokeAllForTenant(ctx, "tenant-a")
		require.NoError(t, err)
		assert.Equal(t, 0, count, "should return 0 when all keys already revoked")
	})
}

func TestRevokeAllForSubscription(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	// Add keys for sub-1 in tenant-a
	err := store.AddKey(ctx, "alice", "key-sub1-1", "hash-s1-1", "Alice Sub1 Key", "", []string{"users"}, "sub-1", "tenant-a", nil, false)
	require.NoError(t, err)
	err = store.AddKey(ctx, "bob", "key-sub1-2", "hash-s1-2", "Bob Sub1 Key", "", []string{"users"}, "sub-1", "tenant-a", nil, false)
	require.NoError(t, err)

	// Add key for sub-2 in tenant-a (should not be affected)
	err = store.AddKey(ctx, "alice", "key-sub2-1", "hash-s2-1", "Alice Sub2 Key", "", []string{"users"}, "sub-2", "tenant-a", nil, false)
	require.NoError(t, err)

	// Add key for sub-1 in tenant-b (should not be affected - different tenant)
	err = store.AddKey(ctx, "charlie", "key-sub1-tenant-b", "hash-s1-b", "Charlie Sub1 Key", "", []string{"users"}, "sub-1", "tenant-b", nil, false)
	require.NoError(t, err)

	t.Run("RevokeAllForSubscription_Success", func(t *testing.T) {
		count, err := store.RevokeAllForSubscription(ctx, "sub-1", "tenant-a")
		require.NoError(t, err)
		assert.Equal(t, 2, count, "should revoke 2 keys for sub-1 in tenant-a")

		// Verify sub-1 keys in tenant-a are revoked
		_, err = store.GetByHash(ctx, "hash-s1-1")
		require.ErrorIs(t, err, api_keys.ErrInvalidKey, "sub-1 key should be revoked")
		_, err = store.GetByHash(ctx, "hash-s1-2")
		require.ErrorIs(t, err, api_keys.ErrInvalidKey, "sub-1 key should be revoked")

		// Verify sub-2 key in tenant-a is still active
		key, err := store.GetByHash(ctx, "hash-s2-1")
		require.NoError(t, err)
		assert.Equal(t, "Alice Sub2 Key", key.Name, "sub-2 key should still be active")

		// Verify sub-1 key in tenant-b is still active
		key, err = store.GetByHash(ctx, "hash-s1-b")
		require.NoError(t, err)
		assert.Equal(t, "Charlie Sub1 Key", key.Name, "sub-1 key in tenant-b should still be active")
	})

	t.Run("RevokeAllForSubscription_NoKeys", func(t *testing.T) {
		count, err := store.RevokeAllForSubscription(ctx, "sub-99", "tenant-a")
		require.NoError(t, err)
		assert.Equal(t, 0, count, "should return 0 when no keys exist for subscription")
	})

	t.Run("RevokeAllForSubscription_AlreadyRevoked", func(t *testing.T) {
		// sub-1 keys already revoked above
		count, err := store.RevokeAllForSubscription(ctx, "sub-1", "tenant-a")
		require.NoError(t, err)
		assert.Equal(t, 0, count, "should return 0 when all keys already revoked")
	})
}

func TestAPIKeyOperations(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	t.Run("AddKey", func(t *testing.T) {
		err := store.AddKey(ctx, "user1", "key-id-1", "hash123", "my-key", "test key", []string{"system:authenticated", "premium-user"}, "sub-1", "", nil, false)
		require.NoError(t, err)

		// Verify key was added by fetching it
		key, err := store.Get(ctx, "key-id-1")
		require.NoError(t, err)
		assert.Equal(t, "my-key", key.Name)
	})

	t.Run("GetByHash", func(t *testing.T) {
		key, err := store.GetByHash(ctx, "hash123")
		require.NoError(t, err)
		assert.Equal(t, "my-key", key.Name)
		assert.Equal(t, "user1", key.Username)
		assert.Equal(t, []string{"system:authenticated", "premium-user"}, key.Groups)
	})

	t.Run("GetByHashNotFound", func(t *testing.T) {
		_, err := store.GetByHash(ctx, "nonexistent-hash")
		require.ErrorIs(t, err, api_keys.ErrKeyNotFound)
	})

	t.Run("RevokeKey", func(t *testing.T) {
		err := store.Revoke(ctx, "key-id-1")
		require.NoError(t, err)

		// Getting by hash should now fail
		_, err = store.GetByHash(ctx, "hash123")
		require.ErrorIs(t, err, api_keys.ErrInvalidKey)
	})

	// Verify that revoking a key ID that doesn't exist in the store returns ErrKeyNotFound.
	t.Run("RevokeNonExistentKey", func(t *testing.T) {
		err := store.Revoke(ctx, "no-such-id")
		require.ErrorIs(t, err, api_keys.ErrKeyNotFound)
	})

	// Verify that revoking an already-revoked key returns ErrKeyNotFound,
	// matching PostgreSQL behavior: only keys with status='active' can be revoked.
	t.Run("RevokeAlreadyRevokedKey", func(t *testing.T) {
		// Create a fresh key, revoke it, then try revoking again
		err := store.AddKey(ctx, "user3", "key-revoke-twice", "hash-revoke-twice", "revoke-twice", "", nil, "sub-1", "", nil, false)
		require.NoError(t, err)

		err = store.Revoke(ctx, "key-revoke-twice")
		require.NoError(t, err)

		// Second revoke should fail — key is no longer active
		err = store.Revoke(ctx, "key-revoke-twice")
		require.ErrorIs(t, err, api_keys.ErrKeyNotFound)
	})

	t.Run("UpdateLastUsed", func(t *testing.T) {
		// Add another key for this test
		err := store.AddKey(ctx, "user2", "key-id-2", "hash456", "key2", "", []string{"system:authenticated", "free-user"}, "sub-2", "", nil, false)
		require.NoError(t, err)

		err = store.UpdateLastUsed(ctx, "key-id-2")
		require.NoError(t, err)

		key, err := store.GetByHash(ctx, "hash456")
		require.NoError(t, err)
		assert.NotEmpty(t, key.LastUsedAt)
	})
}

// TestInvalidateAll tests bulk revocation of all active keys for a given user.
// InvalidateAll revokes all keys with status='active' for a username and returns the count.
func TestInvalidateAll(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	// Verify that InvalidateAll revokes all active keys for the target user
	// while leaving other users' keys untouched.
	t.Run("BasicHappyPath", func(t *testing.T) {
		// Add 3 keys for alice, 2 for bob
		for i := range 3 {
			id := "alice-key-" + string(rune('a'+i))
			require.NoError(t, store.AddKey(ctx, "alice", id, "ahash"+id, "key-"+id, "", nil, "sub-1", "", nil, false))
		}
		for i := range 2 {
			id := "bob-key-" + string(rune('a'+i))
			require.NoError(t, store.AddKey(ctx, "bob", id, "bhash"+id, "key-"+id, "", nil, "sub-1", "", nil, false))
		}

		count, err := store.InvalidateAll(ctx, "alice", "")
		require.NoError(t, err)
		assert.Equal(t, 3, count)

		// Verify all of alice's keys are now revoked
		for i := range 3 {
			id := "alice-key-" + string(rune('a'+i))
			key, err := store.Get(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, api_keys.StatusRevoked, key.Status, "alice's key %s should be revoked", id)
		}

		// Verify bob's keys are completely unaffected
		for i := range 2 {
			id := "bob-key-" + string(rune('a'+i))
			key, err := store.Get(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, api_keys.StatusActive, key.Status, "bob's key %s should remain active", id)
		}
	})

	// Verify that InvalidateAll for a user with no keys returns count=0 and no error.
	t.Run("NoKeysForUser", func(t *testing.T) {
		count, err := store.InvalidateAll(ctx, "nobody", "")
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	// Verify that InvalidateAll only counts keys transitioning from active to revoked.
	// Pre-revoked keys should not be counted again.
	t.Run("MixedStatuses", func(t *testing.T) {
		s := createTestStore(t)
		defer s.Close()

		require.NoError(t, s.AddKey(ctx, "carol", "c1", "ch1", "k1", "", nil, "sub-1", "", nil, false))
		require.NoError(t, s.AddKey(ctx, "carol", "c2", "ch2", "k2", "", nil, "sub-1", "", nil, false))
		require.NoError(t, s.AddKey(ctx, "carol", "c3", "ch3", "k3", "", nil, "sub-1", "", nil, false))

		// Revoke one key manually first
		require.NoError(t, s.Revoke(ctx, "c3"))

		// InvalidateAll should only revoke the 2 remaining active keys
		count, err := s.InvalidateAll(ctx, "carol", "")
		require.NoError(t, err)
		assert.Equal(t, 2, count, "should only revoke active keys, not already-revoked ones")
	})

	// Verify that calling InvalidateAll twice is idempotent:
	// the second call finds no active keys and returns count=0.
	t.Run("IdempotentSecondCall", func(t *testing.T) {
		s := createTestStore(t)
		defer s.Close()

		require.NoError(t, s.AddKey(ctx, "dan", "d1", "dh1", "k1", "", nil, "sub-1", "", nil, false))

		count, err := s.InvalidateAll(ctx, "dan", "")
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Second call should be a no-op
		count, err = s.InvalidateAll(ctx, "dan", "")
		require.NoError(t, err)
		assert.Equal(t, 0, count, "second call should find no active keys")
	})
}

func TestAddKeyWithTenant(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	t.Run("TenantRoundTripsViaGet", func(t *testing.T) {
		err := store.AddKey(ctx, "user1", "tenant-key-1", "thash1", "tenant-key", "", nil, "sub-1", "acme-corp", nil, false)
		require.NoError(t, err)

		key, err := store.Get(ctx, "tenant-key-1")
		require.NoError(t, err)
		assert.Equal(t, "acme-corp", key.Tenant)
	})

	t.Run("EmptyTenantSentinel", func(t *testing.T) {
		err := store.AddKey(ctx, "user1", "tenant-key-2", "thash2", "no-tenant-key", "", nil, "sub-1", "", nil, false)
		require.NoError(t, err)

		key, err := store.Get(ctx, "tenant-key-2")
		require.NoError(t, err)
		assert.Empty(t, key.Tenant)
	})

	t.Run("TenantRoundTripsViaGetByHash", func(t *testing.T) {
		err := store.AddKey(ctx, "user1", "tenant-key-3", "thash3", "hash-tenant-key", "", nil, "sub-1", "tenant-xyz", nil, false)
		require.NoError(t, err)

		key, err := store.GetByHash(ctx, "thash3")
		require.NoError(t, err)
		assert.Equal(t, "tenant-xyz", key.Tenant)
	})
}

// TestSearchByTenant verifies that the store Search method correctly scopes
// results by tenant, returning only keys matching the specified tenant.
func TestSearchByTenant(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	// Add 2 keys for tenant-a
	require.NoError(t, store.AddKey(ctx, "user1", "sa-1", "shah1", "key-a1", "", nil, "sub-1", "tenant-a", nil, false))
	require.NoError(t, store.AddKey(ctx, "user1", "sa-2", "shah2", "key-a2", "", nil, "sub-1", "tenant-a", nil, false))
	// Add 1 key for tenant-b
	require.NoError(t, store.AddKey(ctx, "user1", "sb-1", "shbh1", "key-b1", "", nil, "sub-1", "tenant-b", nil, false))
	// Add 1 key for tenant-c
	require.NoError(t, store.AddKey(ctx, "user1", "sc-1", "shch1", "key-c1", "", nil, "sub-1", "tenant-c", nil, false))

	filters := api_keys.SearchFilters{}
	sortP := api_keys.SortParams{By: api_keys.DefaultSortBy, Order: api_keys.DefaultSortOrder}
	pagination := api_keys.PaginationParams{Limit: 50, Offset: 0}

	t.Run("TenantA_Returns2Keys", func(t *testing.T) {
		result, err := store.Search(ctx, "user1", "tenant-a", &filters, &sortP, &pagination)
		require.NoError(t, err)
		assert.Len(t, result.Keys, 2)
	})

	t.Run("TenantB_Returns1Key", func(t *testing.T) {
		result, err := store.Search(ctx, "user1", "tenant-b", &filters, &sortP, &pagination)
		require.NoError(t, err)
		assert.Len(t, result.Keys, 1)
	})

	t.Run("NonexistentTenant_Returns0Keys", func(t *testing.T) {
		result, err := store.Search(ctx, "user1", "nonexistent", &filters, &sortP, &pagination)
		require.NoError(t, err)
		assert.Empty(t, result.Keys)
	})
}

// TestInvalidateAll_TenantScoped verifies that InvalidateAll only revokes keys
// within the specified tenant, leaving keys in other tenants active.
func TestInvalidateAll_TenantScoped(t *testing.T) {
	ctx := t.Context()
	store := createTestStore(t)
	defer store.Close()

	// Add 2 keys for alice in tenant-a
	require.NoError(t, store.AddKey(ctx, "alice", "ta-1", "tah1", "key-ta1", "", nil, "sub-1", "tenant-a", nil, false))
	require.NoError(t, store.AddKey(ctx, "alice", "ta-2", "tah2", "key-ta2", "", nil, "sub-1", "tenant-a", nil, false))
	// Add 2 keys for alice in tenant-b
	require.NoError(t, store.AddKey(ctx, "alice", "tb-1", "tbh1", "key-tb1", "", nil, "sub-1", "tenant-b", nil, false))
	require.NoError(t, store.AddKey(ctx, "alice", "tb-2", "tbh2", "key-tb2", "", nil, "sub-1", "tenant-b", nil, false))

	// Invalidate only tenant-a keys
	count, err := store.InvalidateAll(ctx, "alice", "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Verify tenant-a keys are revoked
	for _, id := range []string{"ta-1", "ta-2"} {
		key, err := store.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, api_keys.StatusRevoked, key.Status, "tenant-a key %s should be revoked", id)
	}

	// Verify tenant-b keys are still active
	for _, id := range []string{"tb-1", "tb-2"} {
		key, err := store.Get(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, api_keys.StatusActive, key.Status, "tenant-b key %s should remain active", id)
	}
}
