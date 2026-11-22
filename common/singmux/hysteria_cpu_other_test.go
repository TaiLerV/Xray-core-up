//go:build !linux && integration && stress && performance

package singmux_test

import (
	"testing"
	"time"
)

// Other platforms report throughput only.
func processCPUTime(*testing.T, int) time.Duration { return 0 }
