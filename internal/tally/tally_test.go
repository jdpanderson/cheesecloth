package tally

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// captureWarnings sends the default logger's warnings to a buffer for the rest
// of the test.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &log
}

// A burst that stops inside its own window must not read as a single stray
// event: the milestones make its size visible without waiting for a timer.
func Test_Counter_reportsTheSizeOfABurst(t *testing.T) {
	log := captureWarnings(t)
	var c Counter
	now := time.Now()
	c.now = func() time.Time { return now } // frozen: the window never comes round

	for range 500 {
		c.Note("thing happened")
	}
	assert.Equal(t, 3, strings.Count(log.String(), "thing happened"), "at 1, 10 and 100")
	assert.Contains(t, log.String(), "count=100")
	assert.NotContains(t, log.String(), "count=1000")
}

// A trickle too slow to reach a milestone is still reported when the window
// comes round, and the count is the total, so nothing is ever undercounted.
func Test_Counter_reportsTheWindowAndCountsTheTotal(t *testing.T) {
	log := captureWarnings(t)
	var c Counter
	now := time.Now()
	c.now = func() time.Time { return now }

	for range 15 {
		c.Note("thing happened")
	}
	log.Reset()
	now = now.Add(Every + time.Second)
	c.Note("thing happened", "detail", "the latest one")

	assert.Contains(t, log.String(), "count=16", "the total since the process started")
	assert.Contains(t, log.String(), "since=6", "and how many since the last line")
	assert.Contains(t, log.String(), `detail="the latest one"`, "with the triggering occurrence's own fields")
}

// The zero value works, and nothing is written until something happens.
func Test_Counter_zeroValue(t *testing.T) {
	log := captureWarnings(t)
	var c Counter
	assert.Empty(t, log.String())
	c.Note("thing happened")
	assert.Contains(t, log.String(), "count=1")
}

func Test_Counter_concurrent(t *testing.T) {
	captureWarnings(t)
	var c Counter
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Note("thing happened")
		}()
	}
	wg.Wait()
	assert.Equal(t, 50, c.seen)
}

func Test_powerOfTen(t *testing.T) {
	for _, n := range []int{1, 10, 100, 1000, 1000000} {
		assert.True(t, powerOfTen(n), n)
	}
	for _, n := range []int{0, 2, 9, 11, 99, 101, -1} {
		assert.False(t, powerOfTen(n), n)
	}
}

// Every level can be asked for, including the one that is the zero value of
// slog.Level. A counter for something quiet must not be turned up to warn
// because "unset" and "info" cannot be told apart.
func Test_Counter_everyLevelCanBeAskedFor(t *testing.T) {
	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	for _, tt := range []struct {
		name  string
		level slog.Leveler
		want  string
	}{
		{"unset is warn", nil, "level=WARN"},
		{"info", slog.LevelInfo, "level=INFO"},
		{"debug", slog.LevelDebug, "level=DEBUG"},
		{"error", slog.LevelError, "level=ERROR"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log.Reset()
			c := Counter{Level: tt.level}
			c.Note(tt.name)
			assert.Contains(t, log.String(), tt.want)
		})
	}
}
