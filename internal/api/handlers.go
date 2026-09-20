package api

import (
	"net/http"
	"strings"

	"zonesim/internal/service"
	"zonesim/internal/sim"
	"zonesim/internal/store"
)

func (h *Handler) routes() {
	m := h.mux
	m.HandleFunc("GET /api/health", h.health)

	m.HandleFunc("POST /api/zones", h.withIdempotency(store.KindZone, h.createZone))
	m.HandleFunc("GET /api/zones", h.listZones)
	m.HandleFunc("GET /api/zones/{id}", h.getZone)

	m.HandleFunc("POST /api/plans", h.withIdempotency(store.KindPlan, h.createPlan))
	m.HandleFunc("GET /api/plans", h.listPlans)
	m.HandleFunc("GET /api/plans/{id}", h.getPlan)
	m.HandleFunc("PUT /api/plans/{id}", h.updatePlan)
	m.HandleFunc("POST /api/plans/{id}/copy", h.copyPlan)
	m.HandleFunc("POST /api/plans/{id}/validate", h.validatePlan)
	m.HandleFunc("POST /api/plans/{id}/commit", h.commitPlan)
	m.HandleFunc("POST /api/plans/{id}/rollback", h.rollbackPlan)

	m.HandleFunc("POST /api/simulations", h.withIdempotency(store.KindSimulation, h.createSimulation))
	m.HandleFunc("GET /api/simulations", h.listSimulations)
	m.HandleFunc("GET /api/simulations/{id}", h.getSimulation)
	m.HandleFunc("POST /api/simulations/{id}/view", h.viewAt)
	m.HandleFunc("POST /api/simulations/{id}/adhoc", h.withIdempotency(store.KindSimulation, h.adHoc))
	m.HandleFunc("GET /api/simulations/{id}/export", h.exportSim)

	m.HandleFunc("GET /api/events", h.listEvents)
	m.HandleFunc("POST /api/demo/load", h.withIdempotency(store.KindZone, h.loadDemo))

	m.Handle("GET /", http.FileServer(webRoot()))
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (h *Handler) createZone(w http.ResponseWriter, r *http.Request) (string, any, error) {
	var req zoneRequest
	if err := decode(r, &req); err != nil {
		return "", nil, service.ErrorBadJSON(err.Error())
	}
	doc, err := h.svc.ImportZone(service.ImportZoneInput{Label: req.Label, Origin: req.Origin, Text: req.Text})
	if err != nil {
		return "", nil, err
	}
	return doc.ID, doc, nil
}

func (h *Handler) listZones(w http.ResponseWriter, r *http.Request) {
	zones, err := h.svc.ListZones()
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"zones": zones})
}

func (h *Handler) getZone(w http.ResponseWriter, r *http.Request) {
	doc, err := h.svc.GetZone(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, doc)
}

func (h *Handler) createPlan(w http.ResponseWriter, r *http.Request) (string, any, error) {
	var req planRequest
	if err := decode(r, &req); err != nil {
		return "", nil, service.ErrorBadJSON(err.Error())
	}
	p, err := h.svc.CreatePlan(service.CreatePlanInput{
		CurrentZoneID: req.CurrentZoneID, CandidateZoneID: req.CandidateZoneID, Phases: req.Phases,
	})
	if err != nil {
		return "", nil, err
	}
	return p.ID, p, nil
}

func (h *Handler) listPlans(w http.ResponseWriter, r *http.Request) {
	ps, err := h.svc.ListPlans()
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"plans": ps})
}

func (h *Handler) getPlan(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.GetPlan(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, p)
}

func (h *Handler) updatePlan(w http.ResponseWriter, r *http.Request) {
	var req planUpdate
	if err := decode(r, &req); err != nil {
		writeError(w, r, service.ErrorBadJSON(err.Error()))
		return
	}
	p, err := h.svc.UpdatePlan(r.PathValue("id"), service.UpdatePlanInput{Phases: req.Phases}, req.Revision)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, p)
}

func (h *Handler) copyPlan(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.CopyPlan(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 201, p)
}

func (h *Handler) validatePlan(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.ValidatePlan(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, p)
}

func (h *Handler) commitPlan(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.CommitPlan(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, p)
}

func (h *Handler) rollbackPlan(w http.ResponseWriter, r *http.Request) {
	var req rollbackRequest
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			writeError(w, r, service.ErrorBadJSON(err.Error()))
			return
		}
	}
	p, err := h.svc.RollbackPlan(r.PathValue("id"), req.AtSeconds)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, p)
}

func (h *Handler) createSimulation(w http.ResponseWriter, r *http.Request) (string, any, error) {
	var req simRequest
	if err := decode(r, &req); err != nil {
		return "", nil, service.ErrorBadJSON(err.Error())
	}
	doc, replayed, err := h.svc.RunSimulation(service.RunSimulationInput{
		PlanID: req.PlanID, Seed: req.Seed, AuthServers: req.AuthServers,
		Nodes: req.Nodes, Probes: req.Probes, MaxDelaySeconds: req.MaxDelaySeconds,
		QueryEvery: req.QueryEvery, Horizon: req.Horizon, RollbackAt: req.RollbackAt,
	})
	if err != nil {
		return "", nil, err
	}
	if replayed {
		// Same identity: return existing document without creating a second
		// business result. Mark via header and body flag.
		w.Header().Set("X-Simulation-Reused", "true")
	}
	return doc.ID, map[string]any{"reused": replayed, "simulation": doc}, nil
}

func (h *Handler) listSimulations(w http.ResponseWriter, r *http.Request) {
	docs, err := h.svc.ListSimulations()
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"simulations": docs})
}

func (h *Handler) getSimulation(w http.ResponseWriter, r *http.Request) {
	doc, err := h.svc.GetSimulation(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, doc)
}

type viewRequest struct {
	AtSeconds int       `json:"at_seconds"`
	Query     sim.Query `json:"query"`
}

func (h *Handler) viewAt(w http.ResponseWriter, r *http.Request) {
	var req viewRequest
	if err := decode(r, &req); err != nil {
		writeError(w, r, service.ErrorBadJSON(err.Error()))
		return
	}
	view, err := h.svc.ViewAt(r.PathValue("id"), req.Query, req.AtSeconds)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, view)
}

func (h *Handler) adHoc(w http.ResponseWriter, r *http.Request) (string, any, error) {
	var req adhocRequest
	if err := decode(r, &req); err != nil {
		return "", nil, service.ErrorBadJSON(err.Error())
	}
	view, err := h.svc.RunAdHocQuery(r.PathValue("id"), requestID(r), service.AdHocQuery{
		AtSeconds: req.AtSeconds, Query: sim.Query{QName: req.QName, QType: req.QType},
	})
	if err != nil {
		return "", nil, err
	}
	return "adhoc-" + requestID(r), view, nil
}

func (h *Handler) exportSim(w http.ResponseWriter, r *http.Request) {
	bundle, err := h.svc.ExportSimulation(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, bundle)
}

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request) {
	evs, err := h.svc.ListEvents()
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"events": evs})
}

func (h *Handler) loadDemo(w http.ResponseWriter, r *http.Request) (string, any, error) {
	bundle, err := h.svc.SeedDemo()
	if err != nil {
		return "", nil, err
	}
	return bundle.Current.ID, bundle, nil
}

var _ = strings.TrimSpace
