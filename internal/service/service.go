package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"zonesim/internal/dns"
	"zonesim/internal/store"
)

// Service holds the persistent backend and all authoritative business rules.
type Service struct {
	Store *store.Store
}

func New(st *store.Store) *Service { return &Service{Store: st} }

// Error is the single error envelope; Code distinguishes the failure class.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errInvalid(msg string, details any) *Error {
	return &Error{Code: "invalid_input", Message: msg, Details: details, Status: 400}
}
func errConflict(msg string, details any) *Error {
	return &Error{Code: "state_conflict", Message: msg, Details: details, Status: 409}
}
func errNotFound(msg string) *Error {
	return &Error{Code: "not_found", Message: msg, Status: 404}
}
func errBlocked(blocks []dns.Block) *Error {
	return &Error{Code: "publish_blocked", Message: "publication plan fails safety validation", Details: blocks, Status: 400}
}

func newID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// ZoneDoc is the stored raw input + derived identity.
type ZoneDoc struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // current | candidate
	Name        string   `json:"name"`
	Text        string   `json:"text"`
	Fingerprint string   `json:"fingerprint"`
	Serial      uint32   `json:"serial"`
	RecordCount int      `json:"record_count"`
	Records     []dns.RR `json:"records"`
}

type importZoneReq struct {
	RequestID string `json:"request_id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Text      string `json:"text"`
}

// ImportZone parses and stores a current/candidate zone.
func (s *Service) ImportZone(raw []byte) ([]byte, *Error) {
	var req importZoneReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, errInvalid("request body must be valid JSON", err.Error())
	}
	if req.RequestID == "" {
		return nil, errInvalid("request_id is required", nil)
	}
	if req.Kind != "current" && req.Kind != "candidate" {
		return nil, errInvalid("kind must be current or candidate", nil)
	}
	if req.Name == "" {
		return nil, errInvalid("name is required", nil)
	}
	if req.Text == "" {
		return nil, errInvalid("zone text is required", nil)
	}
	if r := s.Store.LookupRequest(req.RequestID); r != nil {
		return replayOrConflict(r, store.PayloadFingerprint(raw))
	}
	zone, perr := dns.ParseZone(req.Name, req.Text)
	if perr != nil {
		return nil, errInvalid("zone parse failed", perr.Error())
	}
	doc := ZoneDoc{ID: newID("zone"), Kind: req.Kind, Name: zone.Origin, Text: req.Text,
		Fingerprint: zone.Fingerprint(), Serial: zone.ApexSerial(),
		RecordCount: len(zone.Records), Records: zone.Records}
	docBytes, _ := json.MarshalIndent(doc, "", "  ")
	if err := s.stageZone(doc.ID, docBytes); err != nil {
		return nil, errInternal(err)
	}
	resp := map[string]any{"zone_id": doc.ID, "fingerprint": doc.Fingerprint,
		"record_count": doc.RecordCount, "serial": doc.Serial}
	return s.commit(req.RequestID, "POST /api/zones", raw, doc.ID, "zone", docBytes, resp)
}

func (s *Service) stageZone(id string, b []byte) error {
	s.Store.StageRaw(id, b)
	return nil
}

func replayOrConflict(r *store.RequestRecord, fp string) ([]byte, *Error) {
	if r.Fingerprint != fp {
		return nil, errConflict("request_id was already used with a different payload",
			map[string]any{"request_id": r.RequestID, "original_endpoint": r.Endpoint})
	}
	return r.Response, nil
}

func errInternal(err error) *Error {
	return &Error{Code: "internal_error", Message: "internal storage failure", Details: err.Error(), Status: 500}
}

func (s *Service) commit(requestID, endpoint string, raw []byte, resourceID, kind string, entity []byte, resp any) ([]byte, *Error) {
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, errInternal(err)
	}
	body := map[string]any{"response": resp, "record": store.RequestRecord{
		RequestID: requestID, Endpoint: endpoint, Fingerprint: store.PayloadFingerprint(raw),
		Response: respBytes,
	}}
	eventBody, _ := json.Marshal(body)
	rec := &store.RequestRecord{RequestID: requestID, Endpoint: endpoint,
		Fingerprint: store.PayloadFingerprint(raw), Response: respBytes}
	if err := s.Store.CompleteRequest(store.Commit{
		Record: rec, EventBody: eventBody, EntityBytes: entity,
		ResourceID: resourceID, Kind: kind,
	}); err != nil {
		return nil, errInternal(err)
	}
	return respBytes, nil
}

// ListZones returns all stored zone documents.
func (s *Service) ListZones() ([]byte, *Error) {
	var out []ZoneDoc
	for _, id := range s.Store.ListZones() {
		b, ok := s.Store.GetZone(id)
		if !ok {
			continue
		}
		var d ZoneDoc
		if json.Unmarshal(b, &d) == nil {
			out = append(out, d)
		}
	}
	b, err := json.Marshal(map[string]any{"zones": out})
	if err != nil {
		return nil, errInternal(err)
	}
	return b, nil
}

func mustParseZone(docBytes []byte) (*dns.Zone, *ZoneDoc, *Error) {
	var doc ZoneDoc
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, nil, errInternal(err)
	}
	z, perr := dns.ParseZone(doc.Name, doc.Text)
	if perr != nil {
		return nil, nil, errInternal(fmt.Errorf("stored zone unparseable: %v", perr))
	}
	return z, &doc, nil
}

// ErrInvalid builds an invalid_input error for transport-level failures.
func ErrInvalid(msg string) *Error { return errInvalid(msg, nil) }
