package auth

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultSARCacheTTL        = 30 * time.Second
	defaultSARCacheMaxEntries = 2048
)

type sarCheckType string

const (
	sarCheckAuthenticated sarCheckType = "authenticated"
	sarCheckAdmin         sarCheckType = "admin"
)

type sarCacheOptions struct {
	ttl        time.Duration
	maxEntries int
}

type sarDecision struct {
	allowed   bool
	expiresAt time.Time
}

type sarDecisionCache struct {
	now        func() time.Time
	ttl        time.Duration
	maxEntries int

	mu    sync.RWMutex
	items map[string]sarDecision
}

func newSARDecisionCache(opts sarCacheOptions) *sarDecisionCache {
	ttl := opts.ttl
	if ttl <= 0 {
		ttl = defaultSARCacheTTL
	}

	maxEntries := opts.maxEntries
	if maxEntries <= 0 {
		maxEntries = defaultSARCacheMaxEntries
	}

	return &sarDecisionCache{
		now:        time.Now,
		ttl:        ttl,
		maxEntries: maxEntries,
		items:      make(map[string]sarDecision, maxEntries),
	}
}

func (c *sarDecisionCache) get(key string) (bool, bool) {
	now := c.now()

	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return false, false
	}
	if now.After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return false, false
	}
	return entry.allowed, true
}

func (c *sarDecisionCache) set(key string, allowed bool) {
	now := c.now()

	c.mu.Lock()
	if len(c.items) >= c.maxEntries {
		for k, entry := range c.items {
			if now.After(entry.expiresAt) {
				delete(c.items, k)
			}
		}
		if len(c.items) >= c.maxEntries {
			for k := range c.items {
				delete(c.items, k)
				break
			}
		}
	}
	c.items[key] = sarDecision{allowed: allowed, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
}

func sarCacheKey(check sarCheckType, username string, groups []string, namespace string) string {
	normalizedGroups := normalizeGroups(groups)
	if namespace != "" {
		return fmt.Sprintf("%s|%s|%s|%s", check, strings.TrimSpace(namespace), strings.TrimSpace(username), strings.Join(normalizedGroups, "\x1f"))
	}
	return fmt.Sprintf("%s|%s|%s", check, strings.TrimSpace(username), strings.Join(normalizedGroups, "\x1f"))
}

func normalizeGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		normalized = append(normalized, g)
	}
	if len(normalized) == 0 {
		return nil
	}
	sort.Strings(normalized)
	return normalized
}
