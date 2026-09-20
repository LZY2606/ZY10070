package service

import (
	"time"

	"zonesim/internal/store"
)

// ExportSimulation builds the full evidence bundle and persists it.
func (s *Service) ExportSimulation(simID string) (*ExportBundle, error) {
	doc, err := s.loadSimulation(simID)
	if err != nil {
		return nil, err
	}
	p, err := s.loadPlan(doc.PlanID)
	if err != nil {
		return nil, err
	}
	cur, err := s.GetZone(p.CurrentZoneID)
	if err != nil {
		return nil, err
	}
	cand, err := s.GetZone(p.CandidateZoneID)
	if err != nil {
		return nil, err
	}
	events, err := s.store.ListEvents()
	if err != nil {
		return nil, internalErr(err.Error())
	}
	views := make([]EventView, 0, len(events))
	for _, e := range events {
		views = append(views, EventView{Seq: e.Seq, At: e.At, Type: e.Type, RequestID: e.RequestID, RefID: e.RefID})
	}
	adhoc, err := s.loadAdHoc(simID)
	if err != nil {
		return nil, err
	}
	bundle := &ExportBundle{
		ExportedAt: time.Now().UTC(), Plan: p,
		CurrentZone: cur, CandidateZone: cand, Simulation: doc,
		Events: views, AdHoc: adhoc,
	}
	if err := s.store.Put(store.KindExport, "export_"+simID, bundle); err != nil {
		return nil, internalErr(err.Error())
	}
	if _, err := s.store.AppendEvent("simulation.exported", "", simID, nil); err != nil {
		return nil, internalErr(err.Error())
	}
	return bundle, nil
}

// ListEvents exposes the operational journal.
func (s *Service) ListEvents() ([]store.Event, error) {
	evs, err := s.store.ListEvents()
	if err != nil {
		return nil, internalErr(err.Error())
	}
	return evs, nil
}
