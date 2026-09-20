// Package api exposes the HTTP/JSON interface and serves the browser UI.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"zonesim/internal/service"
	"zonesim/internal/sim"
	"zonesim/internal/store"
)

// Handler builds the router.
type Handler struct {
	svc *service.Service
	mux *http.ServeMux
}

// New wires routes.
func New(svc *service.Service) *Handler {
	h := &Handler{svc: svc, mux: http.NewServeMux()}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type problemBody struct {
	Error struct {
		Class   string `json:"class"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var se *service.Error
	status := http.StatusInternalServerError
	class := string(service.ClassInternal)
	code := "INTERNAL"
	msg := err.Error()
	if errors.As(err, &se) {
		code = se.Code
		msg = se.Msg
		switch se.Class {
		case service.ClassInvalid:
			status = http.StatusBadRequest
			class = string(service.ClassInvalid)
		case service.ClassConflict:
			status = http.StatusConflict
			class = string(service.ClassConflict)
		case service.ClassNotFound:
			status = http.StatusNotFound
			class = string(service.ClassNotFound)
		}
	} else if errors.Is(err, store.ErrConflict) {
		status = http.StatusConflict
		class = string(service.ClassConflict)
		code = "STATE_CONFLICT"
	} else if errors.Is(err, store.ErrNotFound) {
		status = http.StatusNotFound
		class = string(service.ClassNotFound)
		code = "NOT_FOUND"
	}
	var body problemBody
	body.Error.Class = class
	body.Error.Code = code
	body.Error.Message = msg
	body.RequestID = r.Header.Get("X-Request-Id")
	writeJSON(w, status, body)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// requestID extracts the idempotency key.
func requestID(r *http.Request) string { return strings.TrimSpace(r.Header.Get("X-Request-Id")) }

// replayBody is returned when a repeated request id hits an existing result.
type replayBody struct {
	Replayed  bool   `json:"replayed"`
	RequestID string `json:"request_id"`
	ID        string `json:"id"`
	Kind      string `json:"kind"`
}

// withIdempotency wraps a mutating handler with claim/replay semantics.
func (h *Handler) withIdempotency(kind store.Kind, fn func(w http.ResponseWriter, r *http.Request) (string, any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := requestID(r)
		if reqID != "" {
			res, err := h.svc.Store().BeginRequest(reqID, kind)
			if err != nil {
				writeError(w, r, err)
				return
			}
			if res.Replay {
				// Load original result so replay returns the same body.
				writeJSON(w, http.StatusOK, replayBody{Replayed: true, RequestID: reqID, ID: res.ResultID, Kind: string(kind)})
				return
			}
		}
		id, body, err := fn(w, r)
		if err != nil {
			h.svc.Store().FailRequest(reqID)
			writeError(w, r, err)
			return
		}
		if reqID != "" {
			if err := h.svc.Store().CompleteRequest(reqID, id); err != nil {
				writeError(w, r, err)
				return
			}
		}
		if body != nil {
			writeJSON(w, http.StatusCreated, body)
		}
	}
}

// --- request DTOs ---

type zoneRequest struct {
	Label  string `json:"label"`
	Origin string `json:"origin"`
	Text   string `json:"text"`
}

type planRequest struct {
	CurrentZoneID   string      `json:"current_zone_id"`
	CandidateZoneID string      `json:"candidate_zone_id"`
	Phases          []sim.Phase `json:"phases"`
}

type planUpdate struct {
	Phases   []sim.Phase `json:"phases"`
	Revision int         `json:"revision"`
}

type simRequest struct {
	PlanID          string           `json:"plan_id"`
	Seed            int64            `json:"seed"`
	AuthServers     []string         `json:"auth_servers"`
	Nodes           []sim.NodeConfig `json:"nodes"`
	Probes          []sim.Query      `json:"probes"`
	MaxDelaySeconds int              `json:"max_delay_seconds"`
	QueryEvery      int              `json:"query_every_seconds"`
	Horizon         int              `json:"horizon_seconds"`
	RollbackAt      int              `json:"rollback_at_seconds"`
}

type adhocRequest struct {
	AtSeconds int    `json:"at_seconds"`
	QName     string `json:"qname"`
	QType     string `json:"qtype"`
}

type rollbackRequest struct {
	AtSeconds int `json:"at_seconds"`
}
