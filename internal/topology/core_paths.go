package topology

import (
	"cmp"
	"context"
	"slices"
)

const (
	maxPathEdgeAttempts = 10000
	maxPathQueuedStates = 2000
)

// PathEdge is one physical connection or one confirmed LAG. ID is unique in
// the query snapshot. Multiple distinct edges can share the same endpoints.
type PathEdge struct {
	ID, A, B int64
	Weak     bool
}

type CorePath struct {
	Nodes []int64
	Edges []int64
	weak  int
}

// FindCorePaths enumerates loop-free paths in breadth layers. A branch ends
// at its first core. Parallel connections are separate routes.
func FindCorePaths(ctx context.Context, edges []PathEdge, cores map[int64]bool, source int64, maxPaths, maxHops int) ([]CorePath, bool, error) {
	paths := []CorePath{}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if cores[source] {
		return []CorePath{{Nodes: []int64{source}, Edges: []int64{}}}, false, nil
	}
	adjacency := map[int64][]PathEdge{}
	for _, edge := range edges {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		adjacency[edge.A] = append(adjacency[edge.A], edge)
		adjacency[edge.B] = append(adjacency[edge.B], edge)
	}
	for _, incident := range adjacency {
		slices.SortFunc(incident, func(a, b PathEdge) int {
			return cmp.Compare(a.ID, b.ID)
		})
	}
	frontier := []CorePath{{Nodes: []int64{source}}}
	attempts := 0
	for depth := 0; depth < maxHops && len(frontier) != 0 && len(paths) < maxPaths; depth++ {
		next := []CorePath{}
		for i, prefix := range frontier {
			last := prefix.Nodes[len(prefix.Nodes)-1]
			for _, edge := range adjacency[last] {
				if err := ctx.Err(); err != nil {
					return nil, false, err
				}
				if attempts == maxPathEdgeAttempts {
					return paths, true, nil
				}
				attempts++
				other := edge.B
				if other == last {
					other = edge.A
				}
				if slices.Contains(prefix.Nodes, other) || (!cores[other] && depth+1 == maxHops) {
					continue
				}
				candidate := CorePath{
					Nodes: append(slices.Clone(prefix.Nodes), other),
					Edges: append(slices.Clone(prefix.Edges), edge.ID),
					weak:  prefix.weak,
				}
				if edge.Weak {
					candidate.weak++
				}
				if cores[other] {
					paths = append(paths, candidate)
					slices.SortFunc(paths, compareCorePath)
					paths = paths[:min(len(paths), maxPaths)]
				} else if len(paths) < maxPaths {
					if len(next)+len(frontier)-i-1 >= maxPathQueuedStates {
						return paths, true, nil
					}
					next = append(next, candidate)
				}
			}
		}
		slices.SortFunc(next, compareCorePath)
		frontier = next
	}
	return paths, false, ctx.Err()
}

func compareCorePath(a, b CorePath) int {
	if len(a.Edges) != len(b.Edges) {
		return len(a.Edges) - len(b.Edges)
	}
	if a.weak != b.weak {
		return a.weak - b.weak
	}
	return slices.Compare(a.Edges, b.Edges)
}
