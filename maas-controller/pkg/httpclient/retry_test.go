package httpclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithRetry_Success(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
	}

	t.Run("FirstAttemptSucceeds", func(t *testing.T) {
		attempts := 0
		fn := func() error {
			attempts++
			return nil
		}

		err := WithRetry(context.Background(), config, fn)
		require.NoError(t, err)
		assert.Equal(t, 1, attempts, "should succeed on first attempt")
	})

	t.Run("SecondAttemptSucceeds", func(t *testing.T) {
		attempts := 0
		fn := func() error {
			attempts++
			if attempts < 2 {
				return errors.New("temporary error")
			}
			return nil
		}

		start := time.Now()
		err := WithRetry(context.Background(), config, fn)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Equal(t, 2, attempts, "should succeed on second attempt")
		assert.GreaterOrEqual(t, elapsed, 10*time.Millisecond, "should wait InitialDelay before retry")
	})

	t.Run("ThirdAttemptSucceeds", func(t *testing.T) {
		attempts := 0
		fn := func() error {
			attempts++
			if attempts < 3 {
				return errors.New("temporary error")
			}
			return nil
		}

		start := time.Now()
		err := WithRetry(context.Background(), config, fn)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Equal(t, 3, attempts, "should succeed on third attempt")
		// InitialDelay (10ms) + 2*InitialDelay (20ms) = 30ms minimum
		assert.GreaterOrEqual(t, elapsed, 30*time.Millisecond, "should wait with exponential backoff")
	})
}

func TestWithRetry_AllAttemptsFail(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	expectedErr := errors.New("persistent error")
	fn := func() error {
		attempts++
		return expectedErr
	}

	err := WithRetry(context.Background(), config, fn)
	require.Error(t, err)
	assert.Equal(t, expectedErr, err, "should return the last error")
	assert.Equal(t, 3, attempts, "should attempt MaxAttempts times")
}

func TestWithRetry_ContextCanceled(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:  5,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0
	fn := func() error {
		attempts++
		if attempts == 2 {
			// Cancel context after second attempt
			cancel()
		}
		return errors.New("error")
	}

	err := WithRetry(ctx, config, fn)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err, "should return context.Canceled")
	assert.LessOrEqual(t, attempts, 2, "should stop retrying when context is canceled")
}

func TestWithRetry_ExponentialBackoff(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:  4,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("error")
	}

	start := time.Now()
	err := WithRetry(context.Background(), config, fn)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Equal(t, 4, attempts)

	// Expected delays: 10ms, 20ms, 40ms (capped at 50ms via math.Min)
	// Total minimum: 10 + 20 + min(40, 50) = 70ms
	// Allow some jitter for test reliability
	assert.GreaterOrEqual(t, elapsed, 60*time.Millisecond, "should apply exponential backoff")
}

func TestWithRetry_MaxDelayEnforced(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:  5,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     25 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("error")
	}

	start := time.Now()
	err := WithRetry(context.Background(), config, fn)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Equal(t, 5, attempts)

	// Expected delays: 10ms, min(20, 25)=20ms, min(40, 25)=25ms, min(50, 25)=25ms
	// Total minimum: 10 + 20 + 25 + 25 = 80ms
	// Allow some jitter for test reliability
	assert.GreaterOrEqual(t, elapsed, 70*time.Millisecond, "should enforce MaxDelay")
}

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	assert.Equal(t, 3, config.MaxAttempts)
	assert.Equal(t, 1*time.Second, config.InitialDelay)
	assert.Equal(t, 10*time.Second, config.MaxDelay)
	assert.Equal(t, 2.0, config.Multiplier)
}

func TestWithRetry_OneAttempt(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:  1,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("error")
	}

	err := WithRetry(context.Background(), config, fn)
	require.Error(t, err)
	assert.Equal(t, 1, attempts, "should call fn exactly once with MaxAttempts=1")
}
