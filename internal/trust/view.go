package trust

// The membership the records make, derived once and read many times. Walking
// the records answers one question about one identity; the same walk answers
// them all, and the answers change only when a record does. So the walk runs
// when a query finds the answers stale rather than for every question asked.

// view is the answers a set of records gives. It is built whole and never
// edited, so a reader holding one has answers that agree with each other.
type view struct {
	members    map[PublicKey]Admission // valid members, by the record that names them
	effective  map[PublicKey]Admission // every identity a record vouches for, member or not
	byName     map[string][]PublicKey  // the valid members holding each name
	conflicts  map[PublicKey]Conflict
	taken      map[uint64]bool // every slot any admission uses, valid or not
	validTaken map[uint64]bool // the slots valid members hold
}

// current is the view, built first if a record has changed since the last one.
// Callers must not hold the lock.
func (s *Set) current() *view {
	if v := s.view.Load(); v != nil {
		return v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked()
}

// viewLocked is current for a caller that already holds the write lock, which
// is how the sweep reads the answers it must not change. Another caller may
// have built the view while this one waited for the lock.
func (s *Set) viewLocked() *view {
	if v := s.view.Load(); v != nil {
		return v
	}
	v := s.build()
	s.view.Store(v)
	return v
}

// build derives the view from the records. Callers hold the write lock.
func (s *Set) build() *view {
	v := &view{
		members:    map[PublicKey]Admission{},
		effective:  map[PublicKey]Admission{},
		byName:     map[string][]PublicKey{},
		taken:      map[uint64]bool{},
		validTaken: map[uint64]bool{},
	}
	for id, by := range s.admissions {
		// every slot any record claims, so that a slot held by a revoked
		// member is handed out only once nothing else is free
		for _, as := range by {
			for _, a := range as {
				v.taken[a.Host] = true
			}
		}
		// membership is one question: the record that stands is the record the
		// answer is made of, so a member always has an effective record and the
		// two can never disagree; see the rule at the top of valid.go
		a, ok := s.effective(id)
		if !ok {
			continue
		}
		v.effective[id] = a
		if s.revoked(id) {
			continue
		}
		v.members[id] = a
		v.validTaken[a.Host] = true
		v.byName[a.Name] = append(v.byName[a.Name], id)
	}
	v.conflicts = conflicts(v.members)
	return v
}

// forget says the answers no longer match the records. The next query builds
// them again. Callers hold the write lock, so no view derived from the records
// as they were can be stored after this.
func (s *Set) forget() { s.view.Store(nil) }

// conflicts is, for every member that has to give up its overlay slot or its
// name, the member that keeps it.
func conflicts(members map[PublicKey]Admission) map[PublicKey]Conflict {
	byHost := map[uint64]Admission{}
	byName := map[string]Admission{}
	for _, a := range members {
		if best, held := byHost[a.Host]; !held || strongerClaim(a, best) {
			byHost[a.Host] = a
		}
		if best, held := byName[a.Name]; !held || strongerClaim(a, best) {
			byName[a.Name] = a
		}
	}
	out := map[PublicKey]Conflict{}
	for id, a := range members {
		switch {
		case byHost[a.Host].Identity != id:
			out[id] = Conflict{Contested: ContestedHost, Other: byHost[a.Host]}
		case byName[a.Name].Identity != id:
			out[id] = Conflict{Contested: ContestedName, Other: byName[a.Name]}
		}
	}
	return out
}
