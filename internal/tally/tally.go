// Package tally reports a condition a remote party can bring about, at a rate
// the local node sets. Writing a line per occurrence would let whoever causes
// them decide how much this node writes to disk, and a peer that can reach a
// port can cause a great many.
package tally

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Every is how often a trickle of occurrences is summarised.
const Every = time.Minute

// Counter counts occurrences of one condition and writes a line when one is
// due. The zero value works and needs no construction.
//
// A line goes out when the window comes round, and also when the total reaches
// the next power of ten. The window alone is not enough: a burst that stops
// inside its own window would be summarised only by whatever arrives next, so
// five hundred occurrences in a second read as one stray event. The milestones
// make a burst's size visible as it happens and stay bounded, since a million
// is seven lines.
//
// The count is the total since the process started, so a line can be late but
// never low.
type Counter struct {
	// Level is what the lines are written at. The zero value is slog.LevelWarn,
	// which is what most of these are: a condition worth an operator's eye that
	// the node is coping with. Set it higher for one it is not coping with.
	Level slog.Level

	mu       sync.Mutex
	seen     int // occurrences since the process started
	reported int // what seen was at the last line
	next     time.Time
	now      func() time.Time // nil means the wall clock; tests move it
}

// Note records one occurrence and writes msg with the counts and args when a
// line is due. The args are the triggering occurrence's, so the line carries a
// current example of the condition rather than a stored one.
func (c *Counter) Note(msg string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now == nil {
		c.now = time.Now
	}
	c.seen++
	now := c.now()
	if now.Before(c.next) && !powerOfTen(c.seen) {
		return
	}
	level := c.Level
	if level == 0 {
		level = slog.LevelWarn
	}
	slog.Log(context.Background(), level, msg, append([]any{"count", c.seen, "since", c.seen - c.reported}, args...)...)
	c.reported, c.next = c.seen, now.Add(Every)
}

// powerOfTen reports whether n is 1, 10, 100 and so on: the counts at which a
// burst is worth a line of its own however recently the last one went out.
func powerOfTen(n int) bool {
	for m := 1; m > 0 && m <= n; m *= 10 {
		if m == n {
			return true
		}
	}
	return false
}
