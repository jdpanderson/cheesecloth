# Agent notes

## Working together

Human and machine are working together to produce a stronger result than either could independently. We each have training and experience the other does not. We are building together.

- Concisely say what you're about to do before doing it so we both understand what's being worked on.
- Items marked **DECISION** need the user's call before any work starts.
- Do not batch items; finish and commit one coherent concept before starting the next.

## Quality

Quality of the code and the interfaces exposed externally by this software must be high quality. No workarounds or hacks. We must work together to find a solution if one isn't clear (ask). Similarly, I expect you to tell me honestly if my request or proposed solution is hacky, incomplete, or a workaround.

## Task Tracking

Proposed and completed work is tracked in `TODO.md`. Take items in order, one at a time, check them off when done.

## Commits
- One notable change per commit; each must stand alone. Only simple related items can be combined.
- Message: concise 1-line summary, optional short detail paragraph.

## Testing
 - Code that can be tested should be tested.
 - Consider (re)writing code to allow for more thorough testing, but not if it sacrifices architecture

## Language

Use straightforward English, without expressions; Clear and concise wording always. This applies to communication, comments, documentation, and commit messages.

 ## Comments & Documentation
 - Function docblock: 1-line summary; a few more lines only if an algorithm needs it.
 - Code body comments: only where the code itself does not sufficiently explain what it does or why.
 - Algorithmic documentation: Name established patterns and algorithms used as building blocks; do not explain them.
 - Additional documentation: A description of how a file's algorithms fit together may be added in a header comment at the top.

## Verify

What CI gates on, so a change that passes here is not rejected there:

```
gofmt -l .                      # must print nothing
go build ./... && go vet ./...
make test                       # go test -race ./...
make lint                       # golangci-lint, must report 0 issues
GOOS=darwin go vet ./... && GOOS=windows go vet ./...
make e2e                        # the container suite; needs docker
```

`make coverage-privileged` runs the tests that need CAP_NET_ADMIN and reports
the total. Without it the wireguard package reads far lower than it is, since
the device and link code is most of that package and needs privilege.
`make test-wg-root` is the same idea for `internal/wg` alone, under real root
rather than a user namespace, which is what its control socket needs.
