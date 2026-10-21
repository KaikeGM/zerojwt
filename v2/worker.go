package zerojwt

import "unsafe"

// PaddedScratch wraps Scratch with explicit cache line padding to prevent
// false sharing across CPU cores under high-concurrency event loops.
type PaddedScratch struct {
	Scratch
	_ [64 - (unsafe.Sizeof(Scratch{})%64)%64]byte
}

// WorkerScratchGroup manages a fixed, cache-line-padded set of Scratch workspaces
// with dedicated worker affinity, eliminating sync.Pool contention and CPU cache invalidations.
type WorkerScratchGroup struct {
	workers []PaddedScratch
}

// NewWorkerScratchGroup instantiates a WorkerScratchGroup sized for numWorkers.
func NewWorkerScratchGroup(v *Verifier, numWorkers int) *WorkerScratchGroup {
	if numWorkers <= 0 {
		numWorkers = 1
	}
	g := &WorkerScratchGroup{
		workers: make([]PaddedScratch, numWorkers),
	}
	for i := range g.workers {
		st := v.NewScratch()
		g.workers[i].Scratch = *st
	}
	return g
}

// For returns the dedicated *Scratch for workerID in O(1) without atomic CAS or locks.
func (g *WorkerScratchGroup) For(workerID int) *Scratch {
	idx := uint(workerID) % uint(len(g.workers))
	return &g.workers[idx].Scratch
}

// Len returns the number of worker scratch slots in the group.
func (g *WorkerScratchGroup) Len() int {
	return len(g.workers)
}
