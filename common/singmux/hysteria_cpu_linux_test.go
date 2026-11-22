//go:build integration && stress && performance

package singmux_test

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Linux MAKE_PROCESS_CPUCLOCK(pid, CPUCLOCK_SCHED) measures all threads of
// the process, including time accrued by threads that have already exited.
func processCPUTime(t *testing.T, pid int) time.Duration {
	t.Helper()
	clockID := (^int32(pid) << 3) | 2
	var stamp unix.Timespec
	if err := unix.ClockGettime(clockID, &stamp); err != nil {
		t.Fatalf("read CPU clock of process %d: %v", pid, err)
	}
	return time.Duration(stamp.Nano())
}
