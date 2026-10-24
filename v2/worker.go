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
	mask    uint
	count   int
}

// NewWorkerScratchGroup instantiates a WorkerScratchGroup sized for numWorkers.
func NewWorkerScratchGroup(v *Verifier, numWorkers int) *WorkerScratchGroup {
	if numWorkers <= 0 {
		numWorkers = 1
	}
	size := 1
	for size < numWorkers {
		size <<= 1
	}
	g := &WorkerScratchGroup{
		workers: make([]PaddedScratch, size),
		mask:    uint(size - 1),
		count:   numWorkers,
	}
	for i := range g.workers {
		st := v.NewScratch()
		g.workers[i].Scratch = *st
	}
	return g
}

// For returns the dedicated *Scratch for workerID in O(1) using power-of-2 bitmasking
// without hardware integer division (DIVQ), atomic CAS, or locks.
func (g *WorkerScratchGroup) For(workerID int) *Scratch {
	return &g.workers[uint(workerID)&g.mask].Scratch
}

// Len returns the number of worker scratch slots requested in the group.
func (g *WorkerScratchGroup) Len() int {
	return g.count
}
