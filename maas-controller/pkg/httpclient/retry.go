package httpclient

import (
	"context"
	"math"
	"time"
)

type RetryConfig struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// DefaultRetryConfig returns the default retry configuration:
// - 3 attempts
// - 1 second initial delay
// - 10 second max delay
// - 2x multiplier (1s → 2s → 4s)
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
	}
}

// WithRetry executes fn with exponential backoff retry logic.
// Returns nil on first success, or the last error after all attempts fail.
// Respects context cancellation and sleeps between attempts.
func WithRetry(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if attempt < config.MaxAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				delay = time.Duration(math.Min(float64(delay)*config.Multiplier, float64(config.MaxDelay)))
			}
		}
	}

	return lastErr
}
