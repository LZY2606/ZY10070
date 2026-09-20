package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"zonesim/internal/service"
)

// Handler wires HTTP routes to the service layer.
type Handler struct {
	svc *service.Service
	mux *http.ServeMux
}

func New(svc *service.Service, ui http.Handler) *Handler {
	h := &Handler{svc: svc, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /api/health", h.health)
	h.mux.HandleFunc("GET /api/zones", h.listZones)
	h.mux.HandleFunc("POST /api/zones", h.importZone)
	h.mux.HandleFunc("GET /api/plans", h.listPlans)
	h.mux.HandleFunc("POST /api/plans", h.createPlan)
	h.mux.HandleFunc("POST /api/plans/{id}/simulations", h.runSimulation)
	h.mux.HandleFunc("POST /api/plans/{id}/copy", h.copyPlan)
	h.mux.HandleFunc("POST /api/plans/{id}/phases/{phase}/decision", h.addDecision)
	h.mux.HandleFunc("GET /api/simulations/{id}", h.getSimulation)
	h.mux.HandleFunc("POST /api/simulations/{id}/export", h.exportSimulation)
	h.mux.HandleFunc("GET /api/exports/{id}", h.getExport)
	if ui != nil {
		h.mux.Handle("/", ui)
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			writeErr(w, &service.Error{Code: "internal_error",
				Message: "unexpected internal failure", Status: 500})
		}
	}()
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (h *Handler) listZones(w http.ResponseWriter, _ *http.Request) {
	b, e := h.svc.ListZones()
	writeSvc(w, b, e)
}

func (h *Handler) importZone(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeErr(w, service.ErrInvalid("cannot read body"))
		return
	}
	b, e := h.svc.ImportZone(raw)
	writeSvc(w, b, e)
}

func (h *Handler) listPlans(w http.ResponseWriter, _ *http.Request) {
	b, e := h.svc.ListPlans()
	writeSvc(w, b, e)
}

func (h *Handler) createPlan(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, service.ErrInvalid("cannot read body"))
		return
	}
	_ = err
	b, e := h.svc.CreatePlan(raw)
	writeSvc(w, b, e)
}

func (h *Handler) runSimulation(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	b, e := h.svc.RunSimulation(r.PathValue("id"), raw)
	writeSvc(w, b, e)
}

func (h *Handler) copyPlan(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	b, e := h.svc.CopyPlan(r.PathValue("id"), raw)
	writeSvc(w, b, e)
}

func (h *Handler) addDecision(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	phase, err := strconv.Atoi(r.PathValue("phase"))
	if err != nil {
		writeErr(w, service.ErrInvalid("phase must be an integer"))
		return
	}
	b, e := h.svc.AddDecision(r.PathValue("id"), phase, raw)
	writeSvc(w, b, e)
}

func (h *Handler) getSimulation(w http.ResponseWriter, r *http.Request) {
	b, e := h.svc.GetSimulation(r.PathValue("id"))
	writeSvc(w, b, e)
}

func (h *Handler) exportSimulation(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	b, e := h.svc.ExportSimulation(r.PathValue("id"), raw)
	writeSvc(w, b, e)
}

func (h *Handler) getExport(w http.ResponseWriter, r *http.Request) {
	b, e := h.svc.GetExport(r.PathValue("id"))
	writeSvc(w, b, e)
}

func writeSvc(w http.ResponseWriter, b []byte, e *service.Error) {
	if e != nil {
		writeErr(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, e *service.Error) {
	status := e.Status
	if status == 0 {
		status = 500
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code": e.Code, "message": e.Message, "details": e.Details,
		},
	})
}

var _ = strings.TrimSpace
