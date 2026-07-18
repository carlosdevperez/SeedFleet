//go:build !linux

package scanner

import "context"

type emptyNeighborSource struct{}

func newSystemNeighborSource() NeighborSource {
	return emptyNeighborSource{}
}

func (emptyNeighborSource) List(context.Context) ([]Neighbor, error) {
	return nil, nil
}
