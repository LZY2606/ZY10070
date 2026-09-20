package service

import "fmt"

// ErrorClass categorises failures so HTTP responses can distinguish malformed
// input, conflicting state and unexpected internal faults.
type ErrorClass string

const (
	ClassInvalid  ErrorClass = "invalid_request"
	ClassConflict ErrorClass = "state_conflict"
	ClassInternal ErrorClass = "internal_error"
	ClassNotFound ErrorClass = "not_found"
)

// Error is a classified service error.
type Error struct {
	Class ErrorClass `json:"-"`
	Code  string     `json:"code"`
	Msg   string     `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Msg) }

func invalid(code, msg string) *Error {
	return &Error{Class: ClassInvalid, Code: code, Msg: msg}
}

func conflict(code, msg string) *Error {
	return &Error{Class: ClassConflict, Code: code, Msg: msg}
}

func internalErr(msg string) *Error {
	return &Error{Class: ClassInternal, Code: "INTERNAL", Msg: msg}
}

func notFound(msg string) *Error {
	return &Error{Class: ClassNotFound, Code: "NOT_FOUND", Msg: msg}
}

// ErrorBadJSON builds a malformed-input error from a decode failure.
func ErrorBadJSON(msg string) *Error {
	return invalid("MALFORMED_JSON", "request body could not be decoded: "+msg)
}
