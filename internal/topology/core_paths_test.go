package topology

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestCorePathsRankAndLoopPrevention(t *testing.T) {
	edges := []PathEdge{
		{ID: 6, A: 2, B: 4},
		{ID: 5, A: 4, B: 5},
		{ID: 4, A: 3, B: 2},
		{ID: 3, A: 1, B: 3},
		{ID: 2, A: 1, B: 2},
		{ID: 1, A: 1, B: 2, Weak: true},
	}
	paths, truncated, err := FindCorePaths(context.Background(), edges, map[int64]bool{2: true, 5: true}, 1, 3, 16)
	if err != nil || truncated || len(paths) != 3 {
		t.Fatalf("paths=%v truncated=%v err=%v", paths, truncated, err)
	}
	for i, want := range [][]int64{{2}, {1}, {3, 4}} {
		if !slices.Equal(paths[i].Edges, want) {
			t.Fatalf("path %d edges=%v, want %v", i, paths[i].Edges, want)
		}
	}
	paths, truncated, err = FindCorePaths(context.Background(), edges, map[int64]bool{5: true}, 1, 3, 2)
	if err != nil || truncated || len(paths) != 0 {
		t.Fatalf("max_hops not respected: %v %v %v", paths, truncated, err)
	}
	paths, _, err = FindCorePaths(context.Background(), edges, map[int64]bool{5: true}, 1, 3, 16)
	if err != nil || len(paths) != 3 || !slices.Equal(paths[2].Nodes, []int64{1, 3, 2, 4, 5}) {
		t.Fatalf("expected a longer loop-free redundant route: %v %v", paths, err)
	}
	paths, _, err = FindCorePaths(context.Background(), edges, map[int64]bool{1: true}, 1, 3, 16)
	if err != nil || len(paths) != 1 || len(paths[0].Edges) != 0 || !slices.Equal(paths[0].Nodes, []int64{1}) {
		t.Fatalf("expected zero-hop path: %v %v", paths, err)
	}
}

func TestCorePathSearchBudgets(t *testing.T) {
	var edges []PathEdge
	for id := int64(2); id <= maxPathQueuedStates+3; id++ {
		edges = append(edges, PathEdge{ID: id, A: 1, B: id})
	}
	paths, truncated, err := FindCorePaths(context.Background(), edges, map[int64]bool{2: true}, 1, 3, 16)
	if err != nil || !truncated || len(paths) != 1 || paths[0].Nodes[1] != 2 {
		t.Fatalf("queue bound: paths=%v truncated=%v err=%v", paths, truncated, err)
	}
	edges = nil
	for i := int64(1); i <= 12; i++ {
		for j := i + 1; j <= 12; j++ {
			edges = append(edges, PathEdge{ID: int64(len(edges) + 1), A: i, B: j})
		}
	}
	paths, truncated, err = FindCorePaths(context.Background(), edges, map[int64]bool{99: true}, 1, 3, 16)
	if err != nil || !truncated || len(paths) != 0 {
		t.Fatalf("dense graph: %v %v %v", paths, truncated, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := FindCorePaths(ctx, edges, nil, 1, 3, 16); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}
