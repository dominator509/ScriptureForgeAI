package bible

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository defines the operations for Bible related data.
type Repository struct {
	primaryPool *pgxpool.Pool
	readPool    *pgxpool.Pool
}

// NewRepository creates a new bible repository.
// readPool is used to offload vector searches to a read replica.
func NewRepository(primaryPool, readPool *pgxpool.Pool) *Repository {
	return &Repository{
		primaryPool: primaryPool,
		readPool:    readPool,
	}
}

// SearchVectors performs a semantic search using the read-replica pool.
func (r *Repository) SearchVectors(ctx context.Context, vector []float32) ([]string, error) {
	// Execute actual pgvector query against r.readPool.
	query := "SELECT content FROM bible_verses ORDER BY embedding <-> $1 LIMIT 5"
	rows, err := r.readPool.Query(ctx, query, vector)
	if err != nil {
		return nil, fmt.Errorf("failed to search vectors: %w", err)
	}
	defer rows.Close()

	var results []string
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		results = append(results, content)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return results, nil
}

// UpdateVerse updates a verse using the primary writer pool.
func (r *Repository) UpdateVerse(ctx context.Context, verseID string, content string) error {
	query := "UPDATE bible_verses SET content = $1 WHERE id = $2"
	_, err := r.primaryPool.Exec(ctx, query, content, verseID)
	if err != nil {
		return fmt.Errorf("failed to update verse: %w", err)
	}
	return nil
}
