package encryptfs

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
)

// ParallelConfig controls parallel chunk processing
type ParallelConfig struct {
	// Enabled enables parallel chunk processing
	Enabled bool

	// MaxWorkers is the maximum number of worker goroutines
	// If 0, defaults to runtime.NumCPU()
	MaxWorkers int

	// MinChunksForParallel is the minimum number of chunks to use parallel processing
	// Below this threshold, sequential processing is used
	// Defaults to 4
	MinChunksForParallel int
}

// Validate checks if the parallel configuration is valid
func (p *ParallelConfig) Validate() error {
	if !p.Enabled {
		return nil // Nothing to validate if disabled
	}

	if p.MaxWorkers < 0 {
		return errors.New("parallel max workers cannot be negative")
	}
	if p.MaxWorkers > 1024 {
		return errors.New("parallel max workers must not exceed 1024")
	}
	if p.MinChunksForParallel < 1 {
		return errors.New("parallel min chunks threshold must be at least 1")
	}
	if p.MinChunksForParallel > 1000 {
		return errors.New("parallel min chunks threshold must not exceed 1000")
	}

	return nil
}

// DefaultParallelConfig returns the default parallel processing configuration
func DefaultParallelConfig() ParallelConfig {
	return ParallelConfig{
		Enabled:              true,
		MaxWorkers:           runtime.NumCPU(),
		MinChunksForParallel: 4,
	}
}

// chunkJob represents a chunk encryption/decryption job
type chunkJob struct {
	index      uint32
	plaintext  []byte
	ciphertext []byte
	nonce      []byte
	err        error
}

// parallelEncryptChunks encrypts multiple chunks in parallel
func (cf *ChunkedFile) parallelEncryptChunks(chunks []chunkJob) error {
	if len(chunks) == 0 {
		return nil
	}

	// Determine number of workers
	numWorkers := cf.fs.config.Parallel.MaxWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	// Limit workers to number of chunks
	if numWorkers > len(chunks) {
		numWorkers = len(chunks)
	}

	// Check if parallel processing is worth it
	if len(chunks) < cf.fs.config.Parallel.MinChunksForParallel {
		// Sequential processing
		for i := range chunks {
			ciphertext, err := cf.engine.Encrypt(chunks[i].nonce, chunks[i].plaintext)
			if err != nil {
				return err
			}
			chunks[i].ciphertext = ciphertext
		}
		return nil
	}

	// Parallel processing
	var wg sync.WaitGroup
	jobChan := make(chan int, len(chunks))
	errChan := make(chan error, numWorkers)

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// Convert panic to error
					err := fmt.Errorf("panic in encryption worker: %v", r)
					select {
					case errChan <- err:
					default:
					}
				}
			}()
			for idx := range jobChan {
				ciphertext, err := cf.engine.Encrypt(chunks[idx].nonce, chunks[idx].plaintext)
				if err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
				chunks[idx].ciphertext = ciphertext
			}
		}()
	}

	// Send jobs
	for i := range chunks {
		jobChan <- i
	}
	close(jobChan)

	// Wait for completion
	wg.Wait()
	close(errChan)

	// Check for errors
	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

// parallelDecryptChunks decrypts multiple chunks in parallel
func (cf *ChunkedFile) parallelDecryptChunks(chunks []chunkJob) error {
	if len(chunks) == 0 {
		return nil
	}

	// Determine number of workers
	numWorkers := cf.fs.config.Parallel.MaxWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	// Limit workers to number of chunks
	if numWorkers > len(chunks) {
		numWorkers = len(chunks)
	}

	// Check if parallel processing is worth it
	if len(chunks) < cf.fs.config.Parallel.MinChunksForParallel {
		// Sequential processing
		for i := range chunks {
			plaintext, err := cf.engine.Decrypt(chunks[i].nonce, chunks[i].ciphertext)
			if err != nil {
				return err
			}
			chunks[i].plaintext = plaintext
		}
		return nil
	}

	// Parallel processing
	var wg sync.WaitGroup
	jobChan := make(chan int, len(chunks))
	errChan := make(chan error, numWorkers)

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// Convert panic to error
					err := fmt.Errorf("panic in decryption worker: %v", r)
					select {
					case errChan <- err:
					default:
					}
				}
			}()
			for idx := range jobChan {
				plaintext, err := cf.engine.Decrypt(chunks[idx].nonce, chunks[idx].ciphertext)
				if err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
				chunks[idx].plaintext = plaintext
			}
		}()
	}

	// Send jobs
	for i := range chunks {
		jobChan <- i
	}
	close(jobChan)

	// Wait for completion
	wg.Wait()
	close(errChan)

	// Check for errors
	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}
