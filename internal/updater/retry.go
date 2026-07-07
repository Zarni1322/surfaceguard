package updater

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// backoff computes the delay for retry attempt n using exponential backoff
// with jitter. base is the initial delay, max is the ceiling.
func backoff(attempt int, base, max time.Duration) time.Duration {
	if attempt <= 0 {
		return 0
	}
	// 2^n * base — capped at max.
	exp := float64(base) * math.Pow(2, float64(attempt-1))
	if exp > float64(max) {
		exp = float64(max)
	}
	// Add up to 25% jitter.
	jitter := time.Duration(rand.Int63n(int64(exp / 4)))
	return time.Duration(exp) + jitter
}

// doWithRetry executes fn up to maxRetries+1 times with exponential backoff.
// fn should return true if the operation succeeded (no retry needed),
// or false + error to trigger a retry. Returns the last error on exhaustion.
func doWithRetry(ctx context.Context, maxRetries int, baseDelay, maxDelay time.Duration, label string, fn func(context.Context) (bool, error)) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := backoff(attempt, baseDelay, maxDelay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		ok, err := fn(ctx)
		if err == nil && ok {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			// fn returned false without error — treat as retryable.
			lastErr = nil
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return nil
}
