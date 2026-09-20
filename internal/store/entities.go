package store

import (
	"encoding/json"
)

// PutEntity stages an entity document in memory and returns its bytes.
func marshalEntity(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// Zone helpers.
func (s *Store) SaveZoneDocument(id string, v any) error {
	b, err := marshalEntity(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.zones[id] = b
	s.mu.Unlock()
	return nil
}

func (s *Store) GetZone(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.zones[id]
	return b, ok
}

func (s *Store) ListZones() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedIDs(s.zones)
}

// Plan helpers.
func (s *Store) StagePlan(id string, v any) ([]byte, error) {
	b, err := marshalEntity(v)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.plans[id] = b
	s.mu.Unlock()
	return b, nil
}

func (s *Store) GetPlan(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.plans[id]
	return b, ok
}

func (s *Store) ListPlans() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedIDs(s.plans)
}

// Simulation helpers.
func (s *Store) StageSimulation(id string, v any) ([]byte, error) {
	b, err := marshalEntity(v)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.sims[id] = b
	s.mu.Unlock()
	return b, nil
}

func (s *Store) GetSimulation(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.sims[id]
	return b, ok
}

func (s *Store) ListSimulations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedIDs(s.sims)
}

// Export helpers.
func (s *Store) StageExport(id string, v any) ([]byte, error) {
	b, err := marshalEntity(v)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.exports[id] = b
	s.mu.Unlock()
	return b, nil
}

func (s *Store) GetExport(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.exports[id]
	return b, ok
}

// StageRaw stores raw entity bytes directly (zone documents are built by the
// service layer).
func (s *Store) StageRaw(id string, b []byte) {
	s.mu.Lock()
	s.zones[id] = b
	s.mu.Unlock()
}
