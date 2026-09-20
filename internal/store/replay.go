package store

import (
	"bufio"
	"encoding/json"
	"io"
)

// replayLog scans the append-only log. A final truncated line (process killed
// mid-append) is ignored: it never committed. Each complete event with an
// embedded request record is delivered to fn.
type logEventBody struct {
	Record *RequestRecord `json:"record,omitempty"`
}

func replayLog(r io.Reader, fn func(ev Event, record *RequestRecord) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			// Corrupt/partial trailing line: not a committed record.
			continue
		}
		var body logEventBody
		_ = json.Unmarshal(ev.Payload, &body)
		if err := fn(ev, body.Record); err != nil {
			return err
		}
	}
	return sc.Err()
}
