package main

import (
	"context"
	"errors"

	"golang.org/x/crypto/argon2"
)

var (
	ErrHashingQueueFull = errors.New("hashing queue is full, too many requests")
)

// HashingTask represents a single password hashing request.
type HashingTask struct {
	Password string
	Salt     []byte
	ResultCh chan HashingResult
}

// HashingResult represents the outcome of a hashing task.
type HashingResult struct {
	Hash []byte
	Err  error
}

// WorkerPool manages bounded concurrent hashing operations.
type WorkerPool struct {
	tasks chan HashingTask
}

// NewWorkerPool initializes a bounded worker pool for CPU-intensive hashing.
// workerCount determines concurrency (should map to CPU cores).
// queueSize determines how many requests can wait before we fail-fast.
func NewWorkerPool(workerCount, queueSize int) *WorkerPool {
	wp := &WorkerPool{
		tasks: make(chan HashingTask, queueSize),
	}

	for i := 0; i < workerCount; i++ {
		go wp.worker()
	}

	return wp
}

func (wp *WorkerPool) worker() {
	for task := range wp.tasks {
		// Argon2id parameters (RFC recommendation or slightly lowered for mock)
		// time: 1, memory: 64*1024, threads: 1, keyLen: 32
		hash := argon2.IDKey([]byte(task.Password), task.Salt, 1, 64*1024, 1, 32)
		task.ResultCh <- HashingResult{Hash: hash, Err: nil}
	}
}

// HashPassword submits a password for hashing. Returns ErrHashingQueueFull immediately if the queue is saturated.
func (wp *WorkerPool) HashPassword(ctx context.Context, password string, salt []byte) ([]byte, error) {
	resultCh := make(chan HashingResult, 1)
	task := HashingTask{
		Password: password,
		Salt:     salt,
		ResultCh: resultCh,
	}

	select {
	case wp.tasks <- task:
		// Task accepted, wait for result or context cancellation
		select {
		case res := <-resultCh:
			return res.Hash, res.Err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	default:
		// Queue is full, fail fast to prevent CPU starvation
		return nil, ErrHashingQueueFull
	}
}
